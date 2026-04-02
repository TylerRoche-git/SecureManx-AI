package securitybrain.policy

import rego.v1

default action := "detect_only"
default authority_level := "auto"

# Map asset criticality to response aggressiveness
action := result if {
    input.confidence_score > 0.9
    result := "quarantine"
}

action := result if {
    input.confidence_score > 0.7
    input.confidence_score <= 0.9
    result := "kill_replace"
}

action := result if {
    input.confidence_score > 0.3
    input.confidence_score <= 0.7
    result := "isolate"
}

# Require human for critical assets with low confidence
authority_level := "requires_human" if {
    input.asset_criticality == "critical"
    input.confidence_score < 0.5
}

# Require human for quarantine actions on critical assets
authority_level := "requires_human" if {
    action == "quarantine"
    input.asset_criticality == "critical"
}

# Build the decision
decision := {
    "action": action,
    "authority_level": authority_level,
    "rationale": sprintf("Policy evaluation: confidence=%.2f, criticality=%s", [input.confidence_score, input.asset_criticality])
}
