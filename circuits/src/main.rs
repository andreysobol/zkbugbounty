pub use franklin_crypto::{
    bellman::{
        plonk::better_better_cs::{
            cs::{
                Circuit, ConstraintSystem, Gate, GateInternal, LookupTableApplication,
                PolyIdentifier, Width4MainGateWithDNext,
            },
            gates::selector_optimized_with_d_next::SelectorOptimizedWidth4MainGateWithDNext,
        },
        Engine, Field, PrimeField, SynthesisError,
    },
    plonk::circuit::{
        allocated_num::{AllocatedNum, Num},
        boolean::Boolean,
        custom_rescue_gate::Rescue5CustomGate,
    },
};
use itertools::Itertools;

pub use rescue_poseidon::{circuit_generic_hash, CustomGate, HashParams, RescueParams};

pub mod contract_functions;

pub mod generate;
pub mod serialize;
mod test_circuits;

const ACC_DEPTH: usize = 8;
const ACC_NUM: usize = 1 << ACC_DEPTH;

pub fn apply_transacton<E: Engine>(
    state: &ERC20State<E>,
    transaction: &Transaction<E>,
) -> Result<ERC20State<E>, SynthesisError> {
    todo!()
}

pub fn create_acc<E: Engine, CS: ConstraintSystem<E>>(
    cs: &mut CS,
    state: &ERC20State<E>,
    owner: &Num<E>,
    pub_key: &Num<E>,
    location: &[Boolean; ACC_DEPTH],
    old_commit: &Num<E>,
    old_owners_commit: &Num<E>,
    balances_commit: &Num<E>,
    old_pub_keys_commit: &Num<E>,
) -> Result<Num<E>, SynthesisError> {
    let computed_commit = hash_three_numbers(cs, &old_owners_commit, balances_commit, &old_pub_keys_commit)?;
    old_commit.enforce_equal(cs, &computed_commit)?;
    
    let mut state = state.clone();

    let (mut owners_path, _) = generate_witness_path_and_commit(cs, location, &state.owners)?;
    let owners_commit = compute_commit(cs, location, &owners_path)?;
    owners_commit.enforce_equal(cs, &old_owners_commit)?;
    owners_path[0].enforce_equal(cs, &Num::zero())?;

    owners_path[0] = *owner;
    let owners_commit = compute_commit(cs, location, &owners_path)?;

    let (mut pub_keys_path, _) = generate_witness_path_and_commit(cs, location, &state.pub_keys)?;
    let pub_keys_commit = compute_commit(cs, location, &pub_keys_path)?;
    pub_keys_commit.enforce_equal(cs, &old_pub_keys_commit)?;
    pub_keys_path[0].enforce_equal(cs, &Num::zero())?;

    pub_keys_path[0] = *owner;
    let pub_keys_commit = compute_commit(cs, location, &pub_keys_path)?;

    Ok(hash_three_numbers(cs, &owners_commit, balances_commit, &pub_keys_commit)?)
}

#[derive(Clone)]
pub struct ERC20State<E: Engine>{
    pub owners: [Num<E>; ACC_NUM],
    pub balances: [Num<E>; ACC_NUM],
    pub pub_keys: [Num<E>; ACC_NUM],
}

impl<E: Engine> ERC20State<E> {
    pub fn new<CS: ConstraintSystem<E>>(
        cs: &mut CS, 
        owner: &Num<E>, 
        amount: &Num<E>, 
        pub_key: &Num<E>
    ) -> Result<Self, SynthesisError> {
        let mut owners = vec![*owner];
        owners.resize(ACC_NUM, Num::zero());
        let mut balances = vec![*amount];
        balances.resize(ACC_NUM, Num::zero());
        let mut pub_keys = vec![*pub_key];
        pub_keys.resize(ACC_NUM, Num::zero());

        Ok(Self{
            balances: balances.try_into().unwrap(),
            owners: owners.try_into().unwrap(),
            pub_keys: pub_keys.try_into().unwrap(),
        })
    }

    pub fn hash_commit<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<Num<E>, SynthesisError> {
        let first = hash_commit(cs, &self.owners)?;
        let second = hash_commit(cs, &self.balances)?;
        let third = hash_commit(cs, &self.pub_keys)?; // useless for one tx bug_proof
        
        Ok(hash_three_numbers(cs, &first, &second, &third)?)
    }

    pub fn conditionally_select<CS: ConstraintSystem<E>>(
        cs: &mut CS, 
        flag: Boolean, 
        this: &Self, 
        other: &Self
    ) -> Result<Self, SynthesisError> {
        let balances = Num::conditionally_select_multiple(cs, &flag, &this.balances, &other.balances)?;
        let owners = Num::conditionally_select_multiple(cs, &flag, &this.owners, &other.owners)?;
        let pub_keys = Num::conditionally_select_multiple(cs, &flag, &this.pub_keys, &other.pub_keys)?; // useless for one tx bug_proof

        Ok(Self{
            balances,
            owners,
            pub_keys, // useless for one tx bug_proof
        })
    }
}

pub struct Transaction<E: Engine> {
    pub sender: Num<E>,
    pub signature: Num<E>, // useless for one tx bug_proof
    pub to: Num<E>,
    pub amount: Num<E>,
}

impl<E: Engine> Transaction<E> {
    // useless for one tx bug_proof
    pub fn tx_hash<CS: ConstraintSystem<E>>(&self, cs: &mut CS) -> Result<Num<E>, SynthesisError> {
        hash_three_numbers(cs, &self.sender, &self.to, &self.amount)
    }

    // useless for one tx bug_proof
    pub fn verify_sig<CS: ConstraintSystem<E>>(&self, ) ->Result<Boolean, SynthesisError> {
        todo!()
    }

    pub fn encode_tx<CS: ConstraintSystem<E>>(&self, pub_key: Num<E>) ->Result<EncodedTransaction<E>, SynthesisError> {
        todo!()
    }
}

pub struct EncodedTransaction<E: Engine> {
    pub sender: Num<E>,
    pub signature: Num<E>,
    pub data: Num<E>,
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

    for (flag, commit) in location.iter().zip(path.iter()) {
        second = *commit;
        (first, second) = Num::conditionally_reverse(cs, &first, &second, flag)?;
        first = hash_two_numbers(cs, &first, &second)?;
    }

    Ok(first)
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
    todo!();
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
    println!("WAGMI!");
}
