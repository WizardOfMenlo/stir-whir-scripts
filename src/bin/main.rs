use stir_whir_estimation::{
    basefold::{BasefoldParameters, BasefoldProtocol},
    errors::SecurityAssumption,
    field::*,
    fri::{FriParameters, FriProtocol},
    //stir::{StirParameters, StirProtocol},
    LowDegreeParameters,
};

fn main() {
    let ldt_parameters = LowDegreeParameters {
        field: GOLDILOCKS_2,
        log_degree: 26,
        batch_size: 1,
        constraint_degree: 0,
    };

    /*
    let stir_parameters = StirParameters::fixed_domain_shift(
        1,                                 // log_inv_rate
        4,                                 // folding_factor
        4,                                 // num_rounds
        SecurityAssumption::CapacityBound, // security_assumption
        100,                               // security_level
        20,                                // pow_bits
        256,                               // digest_size_bits
    );
    let stir_protocol = StirProtocol::new(ldt_parameters, stir_parameters);
    */

    let fri_parameters = FriParameters::fixed_folding(
        1,                                 // log_inv_rate
        4,                                 // folding_factor
        4,                                 // num_rounds
        SecurityAssumption::CapacityBound, // security_assumption
        100,                               // security_level
        20,                                // pow_bits
        256,                               // digest_size_bits
    );

    let fri_protocol = FriProtocol::new(ldt_parameters, fri_parameters);

    let pcs_parameters = LowDegreeParameters {
        field: GOLDILOCKS_2,
        log_degree: 26,
        batch_size: 1,
        constraint_degree: 2,
    };

    let basefold_parameters = BasefoldParameters::fixed_folding(
        1,                                 // log_inv_rate
        4,                                 // folding_factor
        4,                                 // num_rounds
        SecurityAssumption::CapacityBound, // security_assumption
        100,                               // security_level
        20,                                // pow_bits
        256,                               // digest_size_bits
    );

    let basefold_protocol = BasefoldProtocol::new(pcs_parameters, basefold_parameters);

    //println!("{}", stir_protocol);
    println!("{}", fri_protocol);
    println!("{}", basefold_protocol);
}
