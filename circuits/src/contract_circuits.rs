use super::*;

pub struct ApplyTxCircuit<E: Engine> {
    state_pub_keys: [Option<E::Fr>; ACC_DEPTH],
    state_amounts: [Option<E::Fr>; ACC_DEPTH],

}

pub struct CreateAccCircuit<E: Engine> {
    pub state_pub_keys: [Option<E::Fr>; ACC_NUM],
    pub state_amounts: [Option<E::Fr>; ACC_NUM],
    pub new_location: [Option<bool>; ACC_DEPTH],
    pub new_pub_key: Option<E::Fr>,
    pub old_state_commit: Option<E::Fr>,
    pub new_state_commit: Option<E::Fr>,
}

use franklin_crypto::plonk::circuit::Assignment;

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
                alloc_boolean(cs, *bit)?
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

        // Allocating range table
        // let columns = vec![
        //     PolyIdentifier::VariablesPolynomial(0),
        //     PolyIdentifier::VariablesPolynomial(1),
        //     PolyIdentifier::VariablesPolynomial(2),
        // ];
        // let range_table = LookupTableApplication::<E>::new_range_table_of_width_3(8, columns.clone())?;
        // let range_table_name = range_table.functional_name();
        // cs.add_table(range_table)?;

        let (mut old_pub_keys_path, _) = generate_witness_path_and_commit(cs, &new_location, &state_pub_keys)?;
        let (_, amounts_commit) = generate_witness_path_and_commit(cs, &new_location, &state_amounts)?;

        let old_pub_keys_commit = compute_commit(cs, &new_location, &old_pub_keys_path)?;
        let old_commit = hash_two_numbers(cs, &old_pub_keys_commit, &amounts_commit)?;
        old_commit.enforce_equal(cs, &old_state_commit)?;

        old_pub_keys_path[0] = new_pub_key;
        let new_pub_keys_commit = compute_commit(cs, &new_location, &old_pub_keys_path)?;
        let new_commit = hash_two_numbers(cs, &old_pub_keys_commit, &amounts_commit)?;
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

pub fn alloc_boolean<E, CS>(
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