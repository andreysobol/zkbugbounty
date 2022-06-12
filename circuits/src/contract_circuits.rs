use super::*;
use franklin_crypto::plonk::circuit::Assignment;

pub struct HackProofCircuit<E: Engine> {
    pub state_commit: Option<E::Fr>,
    pub state_pub_keys: [Option<E::Fr>; ACC_NUM],
    pub state_amounts: [Option<E::Fr>; ACC_NUM],
    pub total_suply: Option<E::Fr>,
    // tx parts
    pub tx_type: Option<E::Fr>,
    pub first_location: [Option<bool>; ACC_DEPTH],
    pub second_location: [Option<bool>; ACC_DEPTH],
    pub first_parameter: Option<E::Fr>,
    pub second_parameter: Option<E::Fr>,
    // encoded tx parts
    pub encoding_pub_key: Option<E::Fr>,
    pub encoded_tx_type: Option<E::Fr>,
    pub encoded_1st_location: Option<E::Fr>,
    pub encoded_2nd_location: Option<E::Fr>,
    pub encoded_1st_parameter: Option<E::Fr>,
    pub encoded_2nd_parameter: Option<E::Fr>,
}

impl<E: Engine> Circuit<E> for HackProofCircuit<E> {
    type MainGate = Width4MainGateWithDNext;

    fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Allocating public and witness variables
        let state_commit = num_alloc_input(cs, &self.state_commit)?;
        let state_pub_keys = alloc_state(cs, &self.state_pub_keys)?;
        let state_amounts = alloc_state(cs, &self.state_amounts)?;
        let total_suply = num_alloc_input(cs, &self.total_suply)?;

        let tx_type = Num::alloc(cs, self.tx_type)?;
        let first_parameter = Num::alloc(cs, self.first_parameter)?;
        let second_parameter = Num::alloc(cs, self.second_parameter)?;

        let encoding_pub_key = num_alloc_input(cs, &self.encoding_pub_key)?;
        let encoded_tx_type = num_alloc_input(cs, &self.encoded_tx_type)?;
        let encoded_1st_parameter = num_alloc_input(cs, &self.encoded_1st_parameter)?;
        let encoded_2nd_parameter = num_alloc_input(cs, &self.encoded_2nd_parameter)?;

        let first_location = alloc_location(cs, &self.first_location)?;
        let second_location = alloc_location(cs, &self.second_location)?;
        let encoded_1st_location = num_alloc_input(cs, &self.encoded_1st_location)?;
        let encoded_2nd_location = num_alloc_input(cs, &self.encoded_2nd_location)?;

        // Generating lookup table for range checks
        let range_table_name = create_range_table(cs, AMOUNT_LOG_LIMIT)?;

        // Check encoding correctness
        enforce_encoding_correctness(
            cs,
            &encoding_pub_key,
            &tx_type,
            &first_parameter,
            &second_parameter,
            &first_location,
            &second_location,
            &encoded_tx_type,
            &encoded_1st_parameter,
            &encoded_2nd_parameter,
            &encoded_1st_location,
            &encoded_2nd_location,
        )?;

        // Compute all possible tx
        let acc_create_commit = create_acc_circuit_inner(
            cs,
            &state_pub_keys,
            &state_amounts,
            &first_location,
            &state_commit,
            &first_parameter,
        )?;

        let transaction_commit = transaction_circuit_inner(
            cs,
            &state_pub_keys,
            &state_amounts,
            &first_location,
            &second_location,
            &state_commit,
            &first_parameter,
            &second_parameter,
            &range_table_name,
        )?;

        // Get the right commit
        let first_type = tx_type.is_zero(cs)?;
        let new_commit = Num::conditionally_select(
            cs, 
            &first_type, 
            &acc_create_commit, 
            &transaction_commit
        )?;

        // Get the current state
        let (new_state_pub_keys, new_state_amounts) = recover_state(
            cs,
            &new_commit,
            &state_pub_keys,
            &state_amounts,
            &tx_type,
            &first_parameter,
            &second_parameter,
            &first_location,
            &second_location,
        )?;

        // Proof bug existance
        proof_bug(
            cs,
            &new_state_pub_keys,
            &new_state_amounts,
            &total_suply
        )?;

        Ok(())
    }

    fn declare_used_gates() -> Result<Vec<Box<dyn GateInternal<E>>>, SynthesisError> {
        Ok(vec![
            Self::MainGate::default().into_internal(),
            Rescue5CustomGate::default().into_internal(),
        ])
    }
}

pub fn proof_bug<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    _state_pub_keys: &[Num<E>; ACC_NUM],
    state_amounts: &[Num<E>; ACC_NUM],
    total_suply: &Num<E>
) -> Result<(), SynthesisError> {
    // For now, we only proof that the sum of all amounts is not equal to total_suply

    let mut sub = *total_suply;

    for el in state_amounts.iter() {
        sub = sub.sub(cs, el)?;
    }

    sub.assert_not_zero(cs)?;

    Ok(())
}

pub struct ApplyTxCircuit<E: Engine> {
    pub state_pub_keys: [Option<E::Fr>; ACC_NUM],
    pub state_amounts: [Option<E::Fr>; ACC_NUM],
    pub from_location: [Option<bool>; ACC_DEPTH],
    pub to_location: [Option<bool>; ACC_DEPTH],
    pub amount: Option<E::Fr>,
    pub signature: Option<E::Fr>,
    pub old_state_commit: Option<E::Fr>,
    pub new_state_commit: Option<E::Fr>,
}

impl<E: Engine> Circuit<E> for ApplyTxCircuit<E> {
    type MainGate = Width4MainGateWithDNext;

    fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Allocating public and witness variables
        let old_state_commit = num_alloc_input(cs, &self.old_state_commit)?;
        let new_state_commit = num_alloc_input(cs, &self.new_state_commit)?;
        let amount = num_alloc_input(cs, &self.amount)?;
        let signature = Num::alloc(cs, self.signature)?;

        let from_location = alloc_input_location(cs, &self.from_location)?;
        let to_location = alloc_input_location(cs, &self.to_location)?;

        let state_pub_keys = alloc_state(cs, &self.state_pub_keys)?;
        let state_amounts = alloc_state(cs, &self.state_amounts)?;

        // Generating lookup table for range checks
        let range_table_name = create_range_table(cs, AMOUNT_LOG_LIMIT)?;

        // Generating new commit with inner circuit
        let new_commit = transaction_circuit_inner(
            cs,
            &state_pub_keys,
            &state_amounts,
            &from_location,
            &to_location,
            &old_state_commit,
            &signature,
            &amount,
            &range_table_name,
        )?;

        new_commit.enforce_equal(cs, &new_state_commit)?;

        Ok(())
    }

    fn declare_used_gates() -> Result<Vec<Box<dyn GateInternal<E>>>, SynthesisError> {
        Ok(vec![
            Self::MainGate::default().into_internal(),
            Rescue5CustomGate::default().into_internal(),
        ])
    }
}

fn transaction_circuit_inner<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    state_pub_keys: &[Num<E>; ACC_NUM],
    state_amounts: &[Num<E>; ACC_NUM],
    from_location: &[Boolean; ACC_DEPTH],
    to_location: &[Boolean; ACC_DEPTH],
    old_state_commit: &Num<E>,
    signature: &Num<E>,
    amount: &Num<E>,
    range_table_name: &str
) -> Result<Num<E>, SynthesisError> {
    let (from_pub_keys_path, _) = generate_witness_path_and_commit(cs, from_location, state_pub_keys)?;
    let (mut from_amounts_path, _) = generate_witness_path_and_commit(cs, from_location, state_amounts)?;
    let (to_amounts_path, _) = generate_witness_path_and_commit(cs, to_location, state_amounts)?;

    let from_pub_keys_commit = compute_commit(cs, from_location, &from_pub_keys_path)?;
    let from_amoutns_commit = compute_commit(cs, from_location, &from_amounts_path)?;
    let to_amoutns_commit = compute_commit(cs, to_location, &to_amounts_path)?;

    to_amoutns_commit.enforce_equal(cs, &from_amoutns_commit)?;
    to_amounts_path[0].assert_not_zero(cs)?;

    let old_commit = hash_two_numbers(cs, &from_pub_keys_commit, &from_amoutns_commit)?;
    old_commit.enforce_equal(cs, old_state_commit)?;

    verify_sig(cs, &from_pub_keys_path[0], signature)?;

    let (from_new_amount, to_new_amount) = send_tokens(
        cs, 
        &from_amounts_path[0], 
        &to_amounts_path[0],
        amount,
        range_table_name
    )?;

    from_amounts_path[0] = from_new_amount;
    let middle_amounts_commit = compute_commit(cs, from_location, &from_amounts_path)?;

    let idx = get_num_from_boolean(&from_location[..]);
    let mut state_amounts = *state_amounts;
    state_amounts[idx] = from_new_amount;

    let (mut to_amounts_middle_path, _) = generate_witness_path_and_commit(cs, to_location, &state_amounts)?;
    let to_amoutns_middle_commit = compute_commit(cs, to_location, &to_amounts_path)?;
    to_amoutns_middle_commit.enforce_equal(cs, &middle_amounts_commit)?;

    to_amounts_middle_path[0] = to_new_amount;

    let to_amoutns_final_commit = compute_commit(cs, to_location, &to_amounts_path)?;
    Ok(to_amoutns_final_commit)
}

pub struct CreateAccCircuit<E: Engine> {
    pub state_pub_keys: [Option<E::Fr>; ACC_NUM],
    pub state_amounts: [Option<E::Fr>; ACC_NUM],
    pub new_location: [Option<bool>; ACC_DEPTH],
    pub new_pub_key: Option<E::Fr>,
    pub old_state_commit: Option<E::Fr>,
    pub new_state_commit: Option<E::Fr>,
}

impl<E: Engine> Circuit<E> for CreateAccCircuit<E> {
    type MainGate = Width4MainGateWithDNext;

    fn synthesize<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Allocating public and witness variables
        let old_state_commit = num_alloc_input(cs, &self.old_state_commit)?;
        let new_state_commit = num_alloc_input(cs, &self.new_state_commit)?;
        let new_pub_key = num_alloc_input(cs, &self.new_pub_key)?;

        let new_location = alloc_input_location(cs, &self.new_location)?;
        let state_pub_keys = alloc_state(cs, &self.state_pub_keys)?;
        let state_amounts = alloc_state(cs, &self.state_amounts)?;

        // Generating new commit with inner circuit
        let new_commit = create_acc_circuit_inner(
            cs,
            &state_pub_keys,
            &state_amounts,
            &new_location,
            &old_state_commit,
            &new_pub_key,
        )?;

        new_commit.enforce_equal(cs, &new_state_commit)?;

        Ok(())
    }

    fn declare_used_gates() -> Result<Vec<Box<dyn GateInternal<E>>>, SynthesisError> {
        Ok(vec![
            Self::MainGate::default().into_internal(),
            Rescue5CustomGate::default().into_internal(),
        ])
    }
}

fn create_acc_circuit_inner<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    state_pub_keys: &[Num<E>; ACC_NUM],
    state_amounts: &[Num<E>; ACC_NUM],
    new_location: &[Boolean; ACC_DEPTH],
    old_state_commit: &Num<E>,
    new_pub_key: &Num<E>,
) -> Result<Num<E>, SynthesisError> {
    let (mut old_pub_keys_path, _) = generate_witness_path_and_commit(cs, new_location, state_pub_keys)?;
    let (_, amounts_commit) = generate_witness_path_and_commit(cs, new_location, state_amounts)?;

    let old_pub_keys_commit = compute_commit(cs, new_location, &old_pub_keys_path)?;

    let old_commit = hash_two_numbers(cs, &old_pub_keys_commit, &amounts_commit)?;
    old_commit.enforce_equal(cs, old_state_commit)?;

    old_pub_keys_path[0] = *new_pub_key;
    let new_pub_keys_commit = compute_commit(cs, new_location, &old_pub_keys_path)?;

    Ok(hash_two_numbers(cs, &new_pub_keys_commit, &amounts_commit)?)
}

pub fn alloc_input_location<E: Engine, CS: ConstraintSystem<E>> (
    cs: &mut CS,
    bit_location: &[Option<bool>; ACC_DEPTH]
) -> Result<[Boolean; ACC_DEPTH], SynthesisError> {
    let mut location = vec![];
    for bit in bit_location.iter() {
        location.push(
            alloc_input_boolean(cs, *bit)?
        );
    }
    Ok(location.try_into().unwrap())
}

pub fn alloc_location<E: Engine, CS: ConstraintSystem<E>> (
    cs: &mut CS,
    bit_location: &[Option<bool>; ACC_DEPTH]
) -> Result<[Boolean; ACC_DEPTH], SynthesisError> {
    let mut location = vec![];
    for bit in bit_location.iter() {
        location.push(
            Boolean::alloc(cs, *bit)?
        );
    }
    Ok(location.try_into().unwrap())
}

pub fn alloc_state<E: Engine, CS: ConstraintSystem<E>> (
    cs: &mut CS,
    wit_state: &[Option<E::Fr>; ACC_NUM]
) -> Result<[Num<E>; ACC_NUM], SynthesisError> {
    let mut state = vec![];
    for el in wit_state.iter() {
        state.push(
            Num::alloc(cs, *el)?
        );
    }
    Ok(state.try_into().unwrap())
}

pub fn alloc_input_boolean<E, CS>(
    cs: &mut CS,
    value: Option<bool>,
) -> Result<Boolean, SynthesisError>
    where E: Engine,
          CS: ConstraintSystem<E>
{
    let num = AllocatedNum::alloc_input(cs,|| {
        if *value.get()? {
            Ok(E::Fr::one())
        } else {
            Ok(E::Fr::zero())
        }
    })?;
    let var = num.get_variable();

    // Constrain: (1 - a) * a = 0
    // This constrains a to be either 0 or 1.

    let mut gate_term = MainGateTerm::new();

    let mut multiplicative_term = ArithmeticTerm::from_variable(var);
    multiplicative_term = multiplicative_term.mul_by_variable(var);
    gate_term.add_assign(multiplicative_term);
    gate_term.sub_assign(ArithmeticTerm::from_variable(var));

    cs.allocate_main_gate(gate_term)?;
    
    Ok(Boolean::Is(AllocatedBit::from_allocated_num_unchecked(num)))
}

pub fn num_alloc_input<E: Engine, CS: ConstraintSystem<E>> (
    cs: &mut CS,
    input: &Option<E::Fr>,
) -> Result<Num<E>, SynthesisError> {
    let num = AllocatedNum::alloc_input(cs, || Ok(*input.get()?))?;
    Ok(Num::Variable(num))
}

pub fn create_range_table<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    log_size: usize
) -> Result<String, SynthesisError> {
    let columns = vec![
        PolyIdentifier::VariablesPolynomial(0),
        PolyIdentifier::VariablesPolynomial(1),
        PolyIdentifier::VariablesPolynomial(2),
    ];

    let range_table = LookupTableApplication::<E>::new_range_table_of_width_3(log_size, columns.clone())?;
    let range_table_name = range_table.functional_name();
    cs.add_table(range_table)?;

    Ok(range_table_name.to_string())
}