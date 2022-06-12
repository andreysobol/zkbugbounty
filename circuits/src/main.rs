pub use franklin_crypto::{
    bellman::{
        kate_commitment::{Crs, CrsForMonomialForm},
        plonk::better_better_cs::{
            cs::{
                Assembly, Circuit, ConstraintSystem, Gate, GateInternal, LookupTableApplication,
                PlonkCsWidth4WithNextStepAndCustomGatesParams, PolyIdentifier, Setup, Width4MainGateWithDNext,
                TrivialAssembly,
                ArithmeticTerm,
                MainGateTerm,
            },
            proof::Proof,
            setup::VerificationKey,
            verifier,
            gates::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext,
        },
        Engine, Field, PrimeField, ScalarEngine, SynthesisError,
        worker::Worker,
        plonk::commitments::transcript::{keccak_transcript::RollingKeccakTranscript, Transcript},
    },
    plonk::circuit::{
        allocated_num::{AllocatedNum, Num},
        boolean::{AllocatedBit, Boolean},
        custom_rescue_gate::Rescue5CustomGate,
    },
};
use itertools::Itertools;

pub use rescue_poseidon::{circuit_generic_hash, CustomGate, HashParams, RescueParams};

pub mod contract_circuits;

pub mod generate;
pub mod serialize;
mod test_circuits;

const ACC_DEPTH: usize = 8;
const ACC_NUM: usize = 1 << ACC_DEPTH;
const AMOUNT_LOG_LIMIT: usize = 8;

pub fn verify_sig<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    pub_key: &Num<E>,
    signature: &Num<E>,
) ->Result<(), SynthesisError> {
    let sig_hash = hash_number(cs, signature)?;
    sig_hash.enforce_equal(cs, pub_key)?;

    Ok(())
}

pub fn enforce_encoding_correctness<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    encoding_pub_key: &Num<E>,
    tx_type:& Num<E>,
    first_parameter: &Num<E>,
    second_parameter: &Num<E>,
    first_location: &[Boolean; ACC_DEPTH],
    second_location: &[Boolean; ACC_DEPTH],
    encoded_tx_type: &Num<E>,
    encoded_1st_parameter: &Num<E>,
    encoded_2nd_parameter: &Num<E>,
    encoded_1st_location: &Num<E>,
    encoded_2nd_location: &Num<E>,
) -> Result<(), SynthesisError> {
    todo!();
}

fn send_tokens<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    from_amount: &Num<E>,
    to_amount: &Num<E>,
    amount: &Num<E>,
    range_table_name: &str,
) ->Result<(Num<E>, Num<E>), SynthesisError> {
    let from_new_amount = from_amount.sub(cs, amount)?;
    let to_new_amount = to_amount.add(cs, amount)?;

    // range checks for 'amount' and 'from_new_amount'
    {
        let dummy = CS::get_dummy_variable();

        let table = cs.get_table(range_table_name)?;
        let num_keys_and_values = table.width();

        let amount_var = amount.get_variable().get_variable();
        let from_new_amount_var = from_new_amount.get_variable().get_variable();
        let var_zero = cs.get_explicit_zero()?;

        let vars_with_amount = [amount_var, var_zero.clone(), var_zero.clone(), dummy];
        let vars_with_from_new_amount = [from_new_amount_var, var_zero.clone(), var_zero.clone(), dummy];

        cs.begin_gates_batch_for_step()?;

        cs.allocate_variables_without_gate(
            &vars_with_amount,
            &[]
        )?;

        cs.apply_single_lookup_gate(&vars_with_amount[..num_keys_and_values], table)?;
        cs.end_gates_batch_for_step()?;


        let table = cs.get_table(range_table_name)?;
        cs.begin_gates_batch_for_step()?;

        cs.allocate_variables_without_gate(
            &vars_with_from_new_amount,
            &[]
        )?;

        cs.apply_single_lookup_gate(&vars_with_from_new_amount[..num_keys_and_values], table)?;
        cs.end_gates_batch_for_step()?;
    }

    Ok((from_new_amount, to_new_amount))
}

pub fn recover_state<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    new_commit: &Num<E>,
    state_pub_keys: &[Num<E>; ACC_NUM],
    state_amounts: &[Num<E>; ACC_NUM],
    tx_type: &Num<E>,
    first_parameter: &Num<E>,
    second_parameter: &Num<E>,
    first_location: &[Boolean; ACC_DEPTH],
    second_location: &[Boolean; ACC_DEPTH],
) -> Result<([Num<E>; ACC_NUM], [Num<E>; ACC_NUM]), SynthesisError> {
    let mut state_pub_keys = realloc_state(cs, state_pub_keys)?;
    let mut state_amounts = realloc_state(cs, state_amounts)?;

    let idx1 = get_num_from_boolean(first_location);
    let idx2 = get_num_from_boolean(second_location);

    if tx_type.get_value().unwrap().is_zero() {
        state_pub_keys[idx1] = Num::alloc(cs, first_parameter.get_value())?;
    } else {
        let mut tmp = state_amounts[idx1].get_value().unwrap();
        tmp.sub_assign(&second_parameter.get_value().unwrap());
        state_amounts[idx1] = Num::alloc(cs, Some(tmp))?;

        tmp = state_amounts[idx2].get_value().unwrap();
        tmp.add_assign(&second_parameter.get_value().unwrap());
        state_amounts[idx1] = Num::alloc(cs, Some(tmp))?;
    }

    let pub_keys_commit = hash_commit(cs, &state_pub_keys)?;
    let amounts_commit = hash_commit(cs, &state_amounts)?;
    let final_commit = hash_two_numbers(cs, &pub_keys_commit, &amounts_commit)?;

    final_commit.enforce_equal(cs, new_commit)?;

    Ok((state_pub_keys, state_amounts))
}

pub fn realloc_state<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    state: &[Num<E>; ACC_NUM]
) -> Result<[Num<E>; ACC_NUM], SynthesisError> {
    let mut res = vec![];
    for el in state.iter() {
        res.push(
            Num::alloc(
                cs,
                el.get_value()
            )?
        )
    }

    Ok(res.try_into().unwrap())
}

pub fn hash_commit<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS, 
    leafs: &[Num<E>; ACC_NUM],
) -> Result<Num<E>, SynthesisError> {
    let mut commits = leafs.to_vec();
    for _ in 0..ACC_DEPTH {
        let mut tmp_commits = vec![];
        for commits in commits.chunks(2) {
            tmp_commits.push(hash_two_numbers(
                cs,
                &commits[0],
                &commits[1]
            )?)
        }
        commits = tmp_commits;
    }
    Ok(commits[0])
}

// No constraints
pub fn generate_witness_path_and_commit<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS, 
    location: &[Boolean; ACC_DEPTH],
    leafs: &[Num<E>; ACC_NUM],
) -> Result<([Num<E>; ACC_DEPTH + 1], Num<E>), SynthesisError> {
    let mut commits = leafs.to_vec();
    let idx = get_num_from_boolean(&location[..]);
    let mut path = vec![commits[idx]];

    for i in 0..ACC_DEPTH {
        let idx = get_num_from_boolean(&location[i..]) ^ 1;
        path.push(commits[idx]);

        let mut tmp_commits = vec![];
        for commits in commits.chunks(2) {
            tmp_commits.push(hash_two_numbers_out_of_cs(
                cs,
                &commits[0],
                &commits[1]
            )?)
        }
        commits = tmp_commits;
    }

    Ok((path.try_into().unwrap(), commits[0]))
}

pub fn compute_commit<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS, 
    location: &[Boolean; ACC_DEPTH],
    path: &[Num<E>; ACC_DEPTH + 1],
) -> Result<Num<E>, SynthesisError> {
    let mut first = path[0];
    let mut second;

    for (flag, commit) in location.iter().zip(path.iter().skip(1)) {
        second = *commit;
        (first, second) = Num::conditionally_reverse(cs, &first, &second, flag)?;
        first = hash_two_numbers(cs, &first, &second)?;
    }

    Ok(first)
}

pub fn hash_number<E: Engine, CS: ConstraintSystem<E>> (
    cs: &mut CS,
    number: &Num<E>
) -> Result<Num<E>, SynthesisError> {
    let mut params = RescueParams::default();

    // Let's double check this in Circuit<E> implementation
    params.use_custom_gate(CustomGate::QuinticWidth4);

    let mut res = circuit_generic_hash::<_, _, _, 1, 3, 1>(cs, &[*number], &params, None)?.to_vec();

    Ok(res.pop().unwrap().into_num(cs)?)
}

pub fn hash_two_numbers<E: Engine, CS: ConstraintSystem<E>> (
    cs: &mut CS,
    first: &Num<E>,
    second: &Num<E>,
) -> Result<Num<E>, SynthesisError> {
    let mut params = RescueParams::default();

    // Let's double check this in Circuit<E> implementation
    params.use_custom_gate(CustomGate::QuinticWidth4);

    let mut res = circuit_generic_hash::<_, _, _, 1, 3, 2>(cs, &[*first, *second], &params, None)?.to_vec();

    Ok(res.pop().unwrap().into_num(cs)?)
}

pub fn hash_three_numbers<E: Engine, CS: ConstraintSystem<E>> (
    cs: &mut CS,
    first: &Num<E>,
    second: &Num<E>,
    third: &Num<E>,
) -> Result<Num<E>, SynthesisError> {
    let mut params = RescueParams::default();

    // Let's double check this in Circuit<E> implementation
    params.use_custom_gate(CustomGate::QuinticWidth4);

    let mut res = circuit_generic_hash::<_, _, _, 1, 3, 3>(cs, &[*first, *second, *third], &params, None)?.to_vec();

    Ok(res.pop().unwrap().into_num(cs)?)
}

pub fn hash_two_numbers_out_of_cs<E: Engine, CS: ConstraintSystem<E>> (
    cs: &mut CS,
    first: &Num<E>,
    second: &Num<E>,
) -> Result<Num<E>, SynthesisError> {
    let mut fake_cs = TrivialAssembly::<
        E,
        PlonkCsWidth4WithNextStepAndCustomGatesParams,
        SelectorOptimizedWidth4MainGateWithDNext,
    >::new();

    let fake_first = Num::alloc(&mut fake_cs, first.get_value())?;
    let fake_second = Num::alloc(&mut fake_cs, second.get_value())?;

    let fake_res = hash_two_numbers(&mut fake_cs, &fake_first, &fake_second)?;

    let res = Num::alloc(cs, fake_res.get_value())?;

    Ok(res)
}

fn get_num_from_boolean(bits: &[Boolean]) -> usize {
    let mut result = 0;
    let mut bits = bits.to_vec();
    bits.reverse();

    for bit in bits.iter() {
        if bit.get_value().unwrap() {
            result += 1;
        }
        result *= 2;
    }

    result
}

fn main() {
    use franklin_crypto::bellman::bn256::{Bn256, Fr};
    use contract_circuits::*;
    use test_circuits::*;

    let mut fake_cs = TrivialAssembly::<
        Bn256,
        PlonkCsWidth4WithNextStepAndCustomGatesParams,
        SelectorOptimizedWidth4MainGateWithDNext,
    >::new();

    let mut state = [Num::Constant(Fr::zero()); ACC_NUM];
    let old_sub_commit = hash_commit(&mut fake_cs, &state).unwrap();
    let old_commit = hash_two_numbers(&mut fake_cs, &old_sub_commit, &old_sub_commit).unwrap();

    state[0] = Num::Constant(Fr::one());
    let new_sub_commit = hash_commit(&mut fake_cs, &state).unwrap();
    let new_commit = hash_two_numbers(&mut fake_cs, &new_sub_commit, &old_sub_commit).unwrap();

    let circuit = CreateAccCircuit::<Bn256> {
        state_pub_keys: [Some(Fr::zero()); ACC_NUM],
        state_amounts: [Some(Fr::zero()); ACC_NUM],
        new_location: [Some(false); ACC_DEPTH],
        new_pub_key: Some(Fr::one()),
        old_state_commit: old_commit.get_value(),
        new_state_commit: new_commit.get_value(),
    };

    generate_setup_vk_and_proof_for_std_main_gate::<
        Bn256,
        _,
        RollingKeccakTranscript<<Bn256 as ScalarEngine>::Fr>,
    >(&circuit, None, "create_account")
    .unwrap()
}
