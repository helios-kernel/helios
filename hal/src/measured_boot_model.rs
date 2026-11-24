//! An in-memory [`MeasuredBoot`] device for tests of the code that
//! consumes the contract.
//!
//! It keeps the two properties a consumer depends on. A register is only
//! ever extended, and its value is determined by the ordered sequence of
//! digests extended into it since the last power cycle. The sealed slot
//! survives a power cycle and releases its secret only while every
//! register it is bound to holds the value it held when the secret was
//! stored.
//!
//! The model keeps each register as that ordered sequence rather than as
//! a running SHA-256 fold. The contract never reveals a register's value,
//! only whether two states are equal, and two sequences are equal exactly
//! when their folds are (up to a SHA-256 collision), so the model's
//! answers are the device's answers without a hash in this crate.
//!
//! A consumer's tests also need to see what it asked of the device and
//! how it reacts when the device fails, so the model journals every
//! operation it is asked for since the last power cycle and fails the
//! next operation of a kind with an error the test chooses.
//!
//! Like [`crate::vmm_test_harness`], the model lives in `hal` so every
//! consumer's tests share it instead of each writing its own.

use alloc::vec::Vec;

use arrayvec::ArrayVec;

use crate::measured_boot::{
    MAX_MEASUREMENT_BANKS, MeasuredBoot, MeasuredBootError, MeasurementAlgorithm, MeasurementBank,
    MeasurementDigest, MeasurementRegister, MeasurementSet, SealedSecret, UnsealRefused,
    validate_extend_digests,
};

/// What one register in one bank has had extended into it since the last power
/// cycle, oldest first.
type RegisterHistory = Vec<MeasurementDigest>;

struct BankState {
    registers: [RegisterHistory; MeasurementSet::CAPACITY as usize],
}

impl BankState {
    fn new() -> Self {
        Self {
            registers: core::array::from_fn(|_| Vec::new()),
        }
    }

    fn clear(&mut self) {
        for register in &mut self.registers {
            register.clear();
        }
    }
}

enum Slot {
    Absent,
    /// A slot someone else defined: its attributes are not this
    /// contract's, so nothing it holds can be trusted.
    Foreign,
    Sealed {
        bound_to: MeasurementSet,
        /// The SHA-256 histories of the registers in `bound_to` when the
        /// secret was stored, lowest register first.
        state: Vec<RegisterHistory>,
        secret: SealedSecret,
    },
}

/// One operation a consumer asked the device for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operation {
    Extend {
        register: MeasurementRegister,
        digests: Vec<MeasurementDigest>,
    },
    LoadSealed {
        bound_to: MeasurementSet,
    },
    StoreSealed {
        bound_to: MeasurementSet,
    },
}

impl Operation {
    pub const fn kind(&self) -> OperationKind {
        match self {
            Self::Extend { .. } => OperationKind::Extend,
            Self::LoadSealed { .. } => OperationKind::LoadSealed,
            Self::StoreSealed { .. } => OperationKind::StoreSealed,
        }
    }
}

/// Which of the contract's operations an [`Operation`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationKind {
    Extend,
    LoadSealed,
    StoreSealed,
}

/// The errors the next operation of each kind fails with.
#[derive(Default)]
struct Faults {
    extend: Option<MeasuredBootError>,
    load_sealed: Option<MeasuredBootError>,
    store_sealed: Option<MeasuredBootError>,
}

impl Faults {
    fn slot(&mut self, kind: OperationKind) -> &mut Option<MeasuredBootError> {
        match kind {
            OperationKind::Extend => &mut self.extend,
            OperationKind::LoadSealed => &mut self.load_sealed,
            OperationKind::StoreSealed => &mut self.store_sealed,
        }
    }
}

/// A measurement device whose registers and slot live in memory.
pub struct MeasuredBootModel {
    kernel_image_registers: MeasurementSet,
    banks: ArrayVec<MeasurementBank, MAX_MEASUREMENT_BANKS>,
    /// Index of the SHA-256 bank in `banks` and `bank_states`.
    sha256_bank: usize,
    bank_states: Vec<BankState>,
    slot: Slot,
    journal: Vec<Operation>,
    faults: Faults,
}

impl MeasuredBootModel {
    /// A device fresh from the factory with a single SHA-256 bank keeping
    /// all 32 registers, every register at its reset value and no slot
    /// defined. `kernel_image_registers` is what
    /// [`MeasuredBoot::kernel_image_registers`] reports.
    pub fn new(kernel_image_registers: MeasurementSet) -> Self {
        Self::with_banks(
            kernel_image_registers,
            &[MeasurementBank {
                algorithm: MeasurementAlgorithm::Sha256,
                registers: MeasurementSet::from_bits(u32::MAX),
            }],
        )
    }

    /// A device fresh from the factory carrying the active PCR banks in
    /// `banks`.
    ///
    /// # Panics
    ///
    /// Panics when `banks` has more than [`MAX_MEASUREMENT_BANKS`] entries,
    /// contains a bank with no registers, names an algorithm twice, or has
    /// no SHA-256 bank covering `kernel_image_registers`.
    pub fn with_banks(kernel_image_registers: MeasurementSet, banks: &[MeasurementBank]) -> Self {
        assert!(
            banks.len() <= MAX_MEASUREMENT_BANKS,
            "at most {MAX_MEASUREMENT_BANKS} active PCR banks are supported"
        );
        let mut active = ArrayVec::new();
        let mut sha256_bank = None;
        for (index, bank) in banks.iter().copied().enumerate() {
            assert!(
                !bank.registers.is_empty(),
                "an active PCR bank must keep at least one register"
            );
            assert!(
                !active
                    .iter()
                    .any(|existing: &MeasurementBank| existing.algorithm == bank.algorithm),
                "duplicate PCR bank algorithm {}",
                bank.algorithm
            );
            if bank.algorithm == MeasurementAlgorithm::Sha256 {
                assert!(
                    bank.registers.contains_all(kernel_image_registers),
                    "the SHA-256 bank must cover all kernel_image_registers"
                );
                sha256_bank = Some(index);
            }
            active.push(bank);
        }
        let sha256_bank = sha256_bank.expect("a measured-boot device must have a SHA-256 bank");
        let bank_states = (0..active.len()).map(|_| BankState::new()).collect();
        Self {
            kernel_image_registers,
            banks: active,
            sha256_bank,
            bank_states,
            slot: Slot::Absent,
            journal: Vec::new(),
            faults: Faults::default(),
        }
    }

    /// Returns every register in every bank to its reset value, as a power
    /// cycle does, and starts a new journal. The slot is non-volatile and
    /// keeps what it holds.
    pub fn power_cycle(&mut self) {
        for bank in &mut self.bank_states {
            bank.clear();
        }
        self.journal.clear();
    }

    /// The ordered digests extended into `register` in `algorithm`'s bank
    /// since the last power cycle, or `None` when that bank does not keep
    /// `register`.
    pub fn register_history(
        &self,
        algorithm: MeasurementAlgorithm,
        register: MeasurementRegister,
    ) -> Option<&[MeasurementDigest]> {
        let index = self
            .banks
            .iter()
            .position(|bank| bank.algorithm == algorithm && bank.registers.contains(register))?;
        Some(&self.bank_states[index].registers[usize::from(register.index())])
    }

    /// Every operation asked for since the last power cycle, oldest
    /// first, the failed ones included.
    pub fn journal(&self) -> &[Operation] {
        &self.journal
    }

    /// Makes the next operation of `kind` fail with `error` and change
    /// nothing, as a device whose interface broke mid-command would.
    pub fn fail_next(&mut self, kind: OperationKind, error: MeasuredBootError) {
        *self.faults.slot(kind) = Some(error);
    }

    /// Journals `operation` and answers the fault armed for its kind.
    fn begin(&mut self, operation: Operation) -> Result<(), MeasuredBootError> {
        let kind = operation.kind();
        self.journal.push(operation);
        match self.faults.slot(kind).take() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Replaces the slot with one this contract did not define, the way
    /// anyone holding the device's owner authorization could.
    pub fn plant_foreign_slot(&mut self) {
        self.slot = Slot::Foreign;
    }

    fn snapshot(&self, bound_to: MeasurementSet) -> Vec<RegisterHistory> {
        let sha256 = &self.bank_states[self.sha256_bank];
        bound_to
            .iter()
            .map(|register| sha256.registers[usize::from(register.index())].clone())
            .collect()
    }
}

impl MeasuredBoot for MeasuredBootModel {
    fn kernel_image_registers(&self) -> MeasurementSet {
        self.kernel_image_registers
    }

    fn banks(&self) -> &[MeasurementBank] {
        &self.banks
    }

    async fn extend(
        &mut self,
        register: MeasurementRegister,
        digests: &[MeasurementDigest],
    ) -> Result<(), MeasuredBootError> {
        self.begin(Operation::Extend {
            register,
            digests: digests.to_vec(),
        })?;
        validate_extend_digests(&self.banks, register, digests)?;
        for (bank, state) in self.banks.iter().zip(self.bank_states.iter_mut()) {
            if bank.registers.contains(register) {
                let digest = digests
                    .iter()
                    .find(|digest| digest.algorithm() == bank.algorithm)
                    .expect("validated above");
                state.registers[usize::from(register.index())].push(*digest);
            }
        }
        Ok(())
    }

    async fn load_sealed(
        &mut self,
        bound_to: MeasurementSet,
    ) -> Result<SealedSecret, UnsealRefused> {
        self.begin(Operation::LoadSealed { bound_to })?;
        let current = self.snapshot(bound_to);
        match &self.slot {
            Slot::Absent => Err(UnsealRefused::Empty),
            Slot::Foreign => Err(UnsealRefused::ForeignSlot),
            Slot::Sealed {
                bound_to: sealed_to,
                state,
                secret,
            } => {
                if *sealed_to == bound_to && *state == current {
                    Ok(SealedSecret::new(*secret.expose()))
                } else {
                    Err(UnsealRefused::StateChanged)
                }
            }
        }
    }

    async fn store_sealed(
        &mut self,
        bound_to: MeasurementSet,
        secret: &SealedSecret,
    ) -> Result<(), MeasuredBootError> {
        self.begin(Operation::StoreSealed { bound_to })?;
        self.slot = Slot::Sealed {
            bound_to,
            state: self.snapshot(bound_to),
            secret: SealedSecret::new(*secret.expose()),
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::future::Future;
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};

    use super::*;

    const PCR4: MeasurementRegister = MeasurementRegister::new(4);
    const PCR9: MeasurementRegister = MeasurementRegister::new(9);
    const BOUND: MeasurementSet = MeasurementSet::of(&[PCR4, PCR9]);

    /// The model never suspends, so one poll completes every operation.
    fn complete<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        match future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        {
            Poll::Ready(output) => output,
            Poll::Pending => panic!("the in-memory measurement device suspended"),
        }
    }

    fn digest(byte: u8) -> MeasurementDigest {
        MeasurementDigest::Sha256([byte; 32])
    }

    fn sha384_digest(byte: u8) -> MeasurementDigest {
        MeasurementDigest::Sha384([byte; 48])
    }

    fn one(digest: MeasurementDigest) -> Vec<MeasurementDigest> {
        alloc::vec![digest]
    }

    /// Firmware measuring the loader and the loader measuring the kernel.
    fn boot(model: &mut MeasuredBootModel, kernel: u8) {
        complete(model.extend(PCR4, &[digest(0x04)])).unwrap();
        complete(model.extend(PCR9, &[digest(kernel)])).unwrap();
    }

    fn secret(byte: u8) -> SealedSecret {
        SealedSecret::new([byte; SealedSecret::LEN])
    }

    #[test]
    fn a_fresh_device_has_nothing_sealed() {
        let mut model = MeasuredBootModel::new(BOUND);
        boot(&mut model, 0x09);
        assert_eq!(
            complete(model.load_sealed(BOUND)).unwrap_err(),
            UnsealRefused::Empty
        );
    }

    #[test]
    fn the_same_boot_chain_reads_back_the_stored_secret() {
        let mut model = MeasuredBootModel::new(BOUND);
        boot(&mut model, 0x09);
        complete(model.store_sealed(BOUND, &secret(0xa5))).unwrap();

        model.power_cycle();
        boot(&mut model, 0x09);
        let loaded = complete(model.load_sealed(BOUND)).unwrap();
        assert_eq!(loaded.expose(), secret(0xa5).expose());
    }

    #[test]
    fn a_changed_register_refuses_the_secret() {
        let mut model = MeasuredBootModel::new(BOUND);
        boot(&mut model, 0x09);
        complete(model.store_sealed(BOUND, &secret(0xa5))).unwrap();

        model.power_cycle();
        boot(&mut model, 0x10);
        assert_eq!(
            complete(model.load_sealed(BOUND)).unwrap_err(),
            UnsealRefused::StateChanged
        );
    }

    #[test]
    fn an_extend_after_storing_refuses_the_secret() {
        let mut model = MeasuredBootModel::new(BOUND);
        boot(&mut model, 0x09);
        complete(model.store_sealed(BOUND, &secret(0xa5))).unwrap();
        complete(model.extend(PCR9, &[digest(0x99)])).unwrap();
        assert_eq!(
            complete(model.load_sealed(BOUND)).unwrap_err(),
            UnsealRefused::StateChanged
        );
    }

    #[test]
    fn a_register_outside_the_binding_does_not_matter() {
        let mut model = MeasuredBootModel::new(BOUND);
        boot(&mut model, 0x09);
        complete(model.store_sealed(BOUND, &secret(0xa5))).unwrap();
        complete(model.extend(MeasurementRegister::new(16), &[digest(0x16)])).unwrap();
        assert!(complete(model.load_sealed(BOUND)).is_ok());
    }

    #[test]
    fn a_different_binding_refuses_the_secret() {
        let mut model = MeasuredBootModel::new(BOUND);
        boot(&mut model, 0x09);
        complete(model.store_sealed(BOUND, &secret(0xa5))).unwrap();
        assert_eq!(
            complete(model.load_sealed(MeasurementSet::empty().with(PCR9))).unwrap_err(),
            UnsealRefused::StateChanged
        );
    }

    #[test]
    fn a_foreign_slot_is_reported_and_replaced_by_a_store() {
        let mut model = MeasuredBootModel::new(BOUND);
        boot(&mut model, 0x09);
        model.plant_foreign_slot();
        assert_eq!(
            complete(model.load_sealed(BOUND)).unwrap_err(),
            UnsealRefused::ForeignSlot
        );

        complete(model.store_sealed(BOUND, &secret(0x3c))).unwrap();
        let loaded = complete(model.load_sealed(BOUND)).unwrap();
        assert_eq!(loaded.expose(), secret(0x3c).expose());
    }

    #[test]
    fn storing_in_a_new_state_makes_the_old_secret_unrecoverable() {
        let mut model = MeasuredBootModel::new(BOUND);
        boot(&mut model, 0x09);
        complete(model.store_sealed(BOUND, &secret(0xa5))).unwrap();

        model.power_cycle();
        boot(&mut model, 0x10);
        complete(model.store_sealed(BOUND, &secret(0x5a))).unwrap();

        model.power_cycle();
        boot(&mut model, 0x09);
        assert_eq!(
            complete(model.load_sealed(BOUND)).unwrap_err(),
            UnsealRefused::StateChanged
        );
    }

    #[test]
    fn the_journal_records_this_boots_operations_in_order() {
        let mut model = MeasuredBootModel::new(BOUND);
        boot(&mut model, 0x09);
        complete(model.store_sealed(BOUND, &secret(0xa5))).unwrap();

        model.power_cycle();
        assert!(model.journal().is_empty());
        boot(&mut model, 0x09);
        complete(model.load_sealed(BOUND)).unwrap();
        assert_eq!(
            model.journal(),
            [
                Operation::Extend {
                    register: PCR4,
                    digests: one(digest(0x04)),
                },
                Operation::Extend {
                    register: PCR9,
                    digests: one(digest(0x09)),
                },
                Operation::LoadSealed { bound_to: BOUND },
            ]
        );
    }

    #[test]
    fn an_armed_fault_fails_the_next_operation_of_its_kind_once() {
        let fault = MeasuredBootError::Interface {
            what: "a status register that never settles",
        };
        let mut model = MeasuredBootModel::new(BOUND);
        model.fail_next(OperationKind::Extend, fault);

        assert_eq!(complete(model.extend(PCR9, &[digest(0x09)])), Err(fault));
        complete(model.extend(PCR9, &[digest(0x09)])).unwrap();
        complete(model.store_sealed(BOUND, &secret(0xa5))).unwrap();

        // The failed extend changed nothing: one extend is in the state.
        model.power_cycle();
        complete(model.extend(PCR9, &[digest(0x09)])).unwrap();
        assert!(complete(model.load_sealed(BOUND)).is_ok());
        assert_eq!(model.journal().len(), 2);
    }

    #[test]
    fn a_failed_load_is_a_device_error_and_a_failed_store_keeps_the_slot() {
        let fault = MeasuredBootError::Timeout {
            state: "command ready",
            waited_ms: 750,
        };
        let mut model = MeasuredBootModel::new(BOUND);
        boot(&mut model, 0x09);
        complete(model.store_sealed(BOUND, &secret(0xa5))).unwrap();

        model.fail_next(OperationKind::LoadSealed, fault);
        assert_eq!(
            complete(model.load_sealed(BOUND)).unwrap_err(),
            UnsealRefused::Device(fault)
        );

        model.fail_next(OperationKind::StoreSealed, fault);
        assert_eq!(
            complete(model.store_sealed(BOUND, &secret(0x5a))),
            Err(fault)
        );
        let loaded = complete(model.load_sealed(BOUND)).unwrap();
        assert_eq!(loaded.expose(), secret(0xa5).expose());
    }

    #[test]
    fn the_model_reports_the_registers_it_was_built_with() {
        assert_eq!(
            MeasuredBootModel::new(BOUND).kernel_image_registers(),
            BOUND
        );
    }

    #[test]
    fn a_two_bank_device_extends_both_banks_and_refuses_incomplete_digests() {
        let all = MeasurementSet::from_bits(u32::MAX);
        let banks = [
            MeasurementBank {
                algorithm: MeasurementAlgorithm::Sha256,
                registers: all,
            },
            MeasurementBank {
                algorithm: MeasurementAlgorithm::Sha384,
                registers: all,
            },
        ];
        let mut model = MeasuredBootModel::with_banks(BOUND, &banks);
        assert_eq!(model.banks(), &banks);

        // Omitting the SHA-384 bank is refused and mutates neither bank.
        assert_eq!(
            complete(model.extend(PCR9, &[digest(0x11)])),
            Err(MeasuredBootError::MissingBankDigest {
                register: PCR9,
                algorithm: MeasurementAlgorithm::Sha384,
            })
        );
        assert_eq!(
            model.register_history(MeasurementAlgorithm::Sha256, PCR9),
            Some(&[][..])
        );
        assert_eq!(
            model.register_history(MeasurementAlgorithm::Sha384, PCR9),
            Some(&[][..])
        );

        // Supplying an inactive bank (SHA-512) or duplicate is refused.
        assert_eq!(
            complete(model.extend(
                PCR9,
                &[
                    digest(0x11),
                    sha384_digest(0x22),
                    MeasurementDigest::Sha512([0x33; 64]),
                ]
            )),
            Err(MeasuredBootError::UnexpectedBankDigest {
                register: PCR9,
                algorithm: MeasurementAlgorithm::Sha512,
            })
        );
        assert_eq!(
            complete(model.extend(PCR9, &[digest(0x11), digest(0x12)])),
            Err(MeasuredBootError::DuplicateBankDigest {
                register: PCR9,
                algorithm: MeasurementAlgorithm::Sha256,
            })
        );

        // Extending with both digests updates both banks in order.
        complete(model.extend(PCR4, &[digest(0x04), sha384_digest(0x40)])).unwrap();
        complete(model.extend(PCR9, &[digest(0x09), sha384_digest(0x90)])).unwrap();
        assert_eq!(
            model.register_history(MeasurementAlgorithm::Sha256, PCR9),
            Some(&[digest(0x09)][..])
        );
        assert_eq!(
            model.register_history(MeasurementAlgorithm::Sha384, PCR9),
            Some(&[sha384_digest(0x90)][..])
        );
        assert_eq!(
            model.register_history(MeasurementAlgorithm::Sha512, PCR9),
            None
        );

        // Sealing binds to the SHA-256 bank and survives power cycle when both banks replay.
        complete(model.store_sealed(BOUND, &secret(0xa5))).unwrap();
        model.power_cycle();
        assert_eq!(
            model.register_history(MeasurementAlgorithm::Sha256, PCR9),
            Some(&[][..])
        );
        assert_eq!(
            model.register_history(MeasurementAlgorithm::Sha384, PCR9),
            Some(&[][..])
        );
        complete(model.extend(PCR4, &[digest(0x04), sha384_digest(0x40)])).unwrap();
        complete(model.extend(PCR9, &[digest(0x09), sha384_digest(0x90)])).unwrap();
        let loaded = complete(model.load_sealed(BOUND)).unwrap();
        assert_eq!(loaded.expose(), secret(0xa5).expose());
    }
}
