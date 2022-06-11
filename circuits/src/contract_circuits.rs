use super::*;
use franklin_crypto::plonk::circuit::Assignment;

pub struct HackProofCircuit<E: Engine> {
    pub begining_state_commit: Option<E::Fr>,
    pub state_pub_keys: [Option<E::Fr>; ACC_NUM],
    pub state_amounts: [Option<E::Fr>; ACC_NUM],
    pub tx_type: Option<E::Fr>,
    // create acc part
    pub new_location: [Option<bool>; ACC_DEPTH],
    pub new_pub_key: Option<E::Fr>,
    // transaction part
    pub from_location: [Option<bool>; ACC_DEPTH],
    pub to_location: [Option<bool>; ACC_DEPTH],
    pub amount: Option<E::Fr>,
    pub signature: Option<E::Fr>,
    // encoded tx
    pub encoded_tx_type: Option<E::Fr>,
    pub encoded_1st_location: [Option<bool>; ACC_DEPTH],
    pub encoded_2nd_location: [Option<bool>; ACC_DEPTH],
    pub encoded_1st_parameter: Option<E::Fr>,
    pub encoded_2nd_parameter: Option<E::Fr>,
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
        // Allocating puplic inputs
        let old_state_commit = AllocatedNum::alloc_input(cs, || Ok(*self.old_state_commit.get()?))?;
        let old_state_commit = Num::Variable(old_state_commit);
        let new_state_commit = AllocatedNum::alloc_input(cs, || Ok(*self.new_state_commit.get()?))?;
        let new_state_commit = Num::Variable(new_state_commit);
        let amount = AllocatedNum::alloc_input(cs, || Ok(*self.amount.get()?))?;
        let amount = Num::Variable(amount);
        let signature = Num::alloc(cs, self.signature)?;

        let mut from_location = vec![];
        for bit in self.from_location.iter() {
            from_location.push(
                alloc_input_boolean(cs, *bit)?
            );
        }
        let from_location: [Boolean; ACC_DEPTH] = from_location.try_into().unwrap();

        let mut to_location = vec![];
        for bit in self.to_location.iter() {
            to_location.push(
                alloc_input_boolean(cs, *bit)?
            );
        }
        let to_location: [Boolean; ACC_DEPTH] = to_location.try_into().unwrap();

        let mut state_pub_keys = vec![];
        for pub_key in self.state_pub_keys.iter() {
            state_pub_keys.push(
                Num::alloc(cs, *pub_key)?
            );
        }
        let state_pub_keys: [Num<E>; ACC_NUM] = state_pub_keys.try_into().unwrap();

        let mut state_amounts = vec![];
        for amount in self.state_amounts.iter() {
            state_amounts.push(
                Num::alloc(cs, *amount)?
            );
        }
        let mut state_amounts: [Num<E>; ACC_NUM] = state_amounts.try_into().unwrap();

        // Allocating range table
        let columns = vec![
            PolyIdentifier::VariablesPolynomial(0),
            PolyIdentifier::VariablesPolynomial(1),
            PolyIdentifier::VariablesPolynomial(2),
        ];

        let range_table = LookupTableApplication::<E>::new_range_table_of_width_3(8, columns.clone())?;
        let range_table_name = range_table.functional_name();
        cs.add_table(range_table)?;


        let (from_pub_keys_path, _) = generate_witness_path_and_commit(cs, &from_location, &state_pub_keys)?;
        let (mut from_amounts_path, _) = generate_witness_path_and_commit(cs, &from_location, &state_amounts)?;
        let (to_amounts_path, _) = generate_witness_path_and_commit(cs, &to_location, &state_amounts)?;

        let from_pub_keys_commit = compute_commit(cs, &from_location, &from_pub_keys_path)?;
        let from_amoutns_commit = compute_commit(cs, &from_location, &from_amounts_path)?;
        let to_amoutns_commit = compute_commit(cs, &to_location, &to_amounts_path)?;

        to_amoutns_commit.enforce_equal(cs, &from_amoutns_commit)?;

        let old_commit = hash_two_numbers(cs, &from_pub_keys_commit, &from_amoutns_commit)?;
        old_commit.enforce_equal(cs, &old_state_commit)?;

        verify_sig(cs, &from_pub_keys_path[0], &signature)?;

        let (from_new_amount, to_new_amount) = send_tokens(
            cs, 
            &from_amounts_path[0], 
            &to_amounts_path[0],
            &amount,
            &range_table_name
        )?;

        from_amounts_path[0] = from_new_amount;
        let middle_amounts_commit = compute_commit(cs, &from_location, &from_amounts_path)?;

        let idx = get_num_from_boolean(&from_location[..]);
        state_amounts[idx] = from_new_amount;

        let (mut to_amounts_middle_path, _) = generate_witness_path_and_commit(cs, &to_location, &state_amounts)?;
        let to_amoutns_middle_commit = compute_commit(cs, &to_location, &to_amounts_path)?;
        to_amoutns_middle_commit.enforce_equal(cs, &middle_amounts_commit)?;

        to_amounts_middle_path[0] = to_new_amount;

        let to_amoutns_final_commit = compute_commit(cs, &to_location, &to_amounts_path)?;
        to_amoutns_final_commit.enforce_equal(cs, &new_state_commit)?;

        Ok(())
    }

    fn declare_used_gates() -> Result<Vec<Box<dyn GateInternal<E>>>, SynthesisError> {
        Ok(vec![
            Self::MainGate::default().into_internal(),
            Rescue5CustomGate::default().into_internal(),
        ])
    }
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
        // Allocating puplic inputs
        let old_state_commit = AllocatedNum::alloc_input(cs, || Ok(*self.old_state_commit.get()?))?;
        let old_state_commit = Num::Variable(old_state_commit);
        let new_state_commit = AllocatedNum::alloc_input(cs, || Ok(*self.new_state_commit.get()?))?;
        let new_state_commit = Num::Variable(new_state_commit);
        let new_pub_key = AllocatedNum::alloc_input(cs, || Ok(*self.new_pub_key.get()?))?;
        let new_pub_key = Num::Variable(new_pub_key);

        let mut new_location = vec![];
        for bit in self.new_location.iter() {
            new_location.push(
                alloc_input_boolean(cs, *bit)?
            );
        }
        let new_location: [Boolean; ACC_DEPTH] = new_location.try_into().unwrap();

        let mut state_pub_keys = vec![];
        for pub_key in self.state_pub_keys.iter() {
            state_pub_keys.push(
                Num::alloc(cs, *pub_key)?
            );
        }
        let state_pub_keys: [Num<E>; ACC_NUM] = state_pub_keys.try_into().unwrap();

        let mut state_amounts = vec![];
        for amount in self.state_amounts.iter() {
            state_amounts.push(
                Num::alloc(cs, *amount)?
            );
        }
        let state_amounts: [Num<E>; ACC_NUM] = state_amounts.try_into().unwrap();

        let (mut old_pub_keys_path, _) = generate_witness_path_and_commit(cs, &new_location, &state_pub_keys)?;
        let (_, amounts_commit) = generate_witness_path_and_commit(cs, &new_location, &state_amounts)?;

        let old_pub_keys_commit = compute_commit(cs, &new_location, &old_pub_keys_path)?;

        let old_commit = hash_two_numbers(cs, &old_pub_keys_commit, &amounts_commit)?;
        old_commit.enforce_equal(cs, &old_state_commit)?;

        old_pub_keys_path[0] = new_pub_key;
        let new_pub_keys_commit = compute_commit(cs, &new_location, &old_pub_keys_path)?;
        let new_commit = hash_two_numbers(cs, &new_pub_keys_commit, &amounts_commit)?;
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