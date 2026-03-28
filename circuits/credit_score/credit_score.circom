pragma circom 2.1.5;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";

/// CreditScore — VECS-compliant demo circuit for Abyssal.
///
/// Private inputs: income, monthly_expenses, years_of_history
/// Secret formula: score = 300 + (income - monthly_expenses) + years_of_history * 10
/// Constraints:
///   - score in [300, 850]
///   - income >= monthly_expenses (positive cash flow)
///   - years_of_history in [0, 50]
///
/// Public outputs (VECS standard, 4 exactly):
///   [0] nullifier          = Poseidon(user_secret, vault_id_field, epoch)
///   [1] result_commitment  = Poseidon(result_value, result_salt)
///   [2] vault_id_hash      = Poseidon(vault_id_field)
///   [3] expiry_epoch        = epoch + VALIDITY_DURATION

template CreditScore(VALIDITY_DURATION) {
    // ===== VECS Standard Private Inputs =====
    signal input user_secret;
    signal input vault_id_field;
    signal input epoch;
    signal input result_value;
    signal input result_salt;

    // ===== Business Logic Private Inputs =====
    signal input income;
    signal input monthly_expenses;
    signal input years_of_history;

    // ===== VECS Standard Public Outputs (exactly 4) =====
    signal output nullifier;
    signal output result_commitment;
    signal output vault_id_hash;
    signal output expiry_epoch;

    // ===== Business Logic: Credit Score Computation =====

    // The "secret formula" — this is what PFE protects.
    // An observer sees only the Poseidon-committed result, never this formula.
    signal computed_score;
    computed_score <== 300 + income - monthly_expenses + years_of_history * 10;

    // Bind result_value to computed score (prevents claiming arbitrary scores)
    result_value === computed_score;

    // Range check: score >= 300 (i.e., score - 300 >= 0, fits in 10 bits)
    // 10 bits covers [0, 1023], sufficient for max delta of 550
    component score_lower = Num2Bits(10);
    score_lower.in <== result_value - 300;

    // Range check: score <= 850 (i.e., 850 - score >= 0, fits in 10 bits)
    component score_upper = Num2Bits(10);
    score_upper.in <== 850 - result_value;

    // Positive cash flow: income >= monthly_expenses
    // (income - monthly_expenses) must fit in 64 bits (non-negative)
    component cashflow_check = Num2Bits(64);
    cashflow_check.in <== income - monthly_expenses;

    // History range: years_of_history in [0, 50]
    component hist_lower = Num2Bits(6);  // 6 bits covers [0, 63]
    hist_lower.in <== years_of_history;
    component hist_upper = Num2Bits(6);
    hist_upper.in <== 50 - years_of_history;

    // ===== VECS Standard: Nullifier =====
    component nh = Poseidon(3);
    nh.inputs[0] <== user_secret;
    nh.inputs[1] <== vault_id_field;
    nh.inputs[2] <== epoch;
    nullifier <== nh.out;

    // ===== VECS Standard: Result Commitment =====
    component rh = Poseidon(2);
    rh.inputs[0] <== result_value;
    rh.inputs[1] <== result_salt;
    result_commitment <== rh.out;

    // ===== VECS Standard: Vault ID Hash =====
    component vh = Poseidon(1);
    vh.inputs[0] <== vault_id_field;
    vault_id_hash <== vh.out;

    // ===== VECS Standard: Expiry Epoch =====
    // VALIDITY_DURATION is in Sui epochs (~24h each)
    // 28 = ~28 days
    expiry_epoch <== epoch + VALIDITY_DURATION;
}

// VALIDITY_DURATION = 28 Sui epochs (~28 days)
component main = CreditScore(28);
