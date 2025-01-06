use stir_whir_estimation::{
    errors::SecurityAssumption,
    field::*,
    fri::{FriParameters, FriProtocol},
    stir::{StirParameters, StirProtocol},
    LowDegreeParameters,
};

fn main() {
    let ldt_parameters = LowDegreeParameters {
        field: GOLDILOCKS_2,
        log_degree: 26,
        batch_size: 1,
    };

    let stir_parameters = StirParameters::fixed_domain_shift(
        1,
        4,
        4,
        SecurityAssumption::CapacityBound,
        100,
        20,
        256,
    );
    let stir_protocol = StirProtocol::new(ldt_parameters, stir_parameters);

    let fri_parameters =
        FriParameters::fixed_folding(1, 4, 4, SecurityAssumption::CapacityBound, 100, 20, 256);
    let fri_protocol = FriProtocol::new(ldt_parameters, fri_parameters);

    println!("{}", stir_protocol);
    println!("{}", fri_protocol);
}
