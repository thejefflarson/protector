//! Tests for the Readiness view_model mapping: the state→Props shaping, the weakening-first
//! ordering, and the honest Present/Absent/Degraded states.

use super::*;
use crate::engine::dashboard::view_model::props::InputStateProps;
use crate::engine::state::{BakeStats, ModelHealth, ReadinessConfig, derive_readiness};
use std::time::SystemTime;

fn covered() -> ReadinessConfig {
    ReadinessConfig {
        model_attached: true,
        kev_count: 5,
        epss_count: 5,
        journal_durable: true,
        armed: false,
        tuf_cache_age_secs: Some(60),
        unverifiable_spike: false,
    }
}

#[test]
fn every_input_becomes_a_row_with_state_word_and_why() {
    let mut bake = BakeStats::default();
    bake.signals_by_variant.insert("alert".into(), 1);
    let r = derive_readiness(&covered(), ModelHealth::Ok, &bake, Some(SystemTime::now()));
    let rows = map_readiness(&r);
    // model / kev / epss / falco / ebpf-agent / journal / tuf-root / arm-state == 8 inputs.
    assert_eq!(rows.len(), 8);
    // Every row carries a non-empty label + why + state word (meaning never by colour alone).
    for row in &rows {
        assert!(!row.label.is_empty());
        assert!(!row.why.is_empty());
        assert!(!row.state.word().is_empty());
        assert!(!row.state.glyph().is_empty());
    }
}

#[test]
fn an_absent_weakening_input_floats_to_the_top() {
    // KEV not loaded (count 0) ⇒ absent AND weakens decisions ⇒ it sorts before present inputs.
    let mut config = covered();
    config.kev_count = 0;
    let mut bake = BakeStats::default();
    bake.signals_by_variant.insert("alert".into(), 1);
    let r = derive_readiness(&config, ModelHealth::Ok, &bake, Some(SystemTime::now()));
    let rows = map_readiness(&r);
    let kev_pos = rows.iter().position(|row| row.id == "kev").unwrap();
    let model_pos = rows.iter().position(|row| row.id == "model").unwrap();
    // The present model row is pushed below the absent-weakening kev row.
    assert!(
        kev_pos < model_pos,
        "an absent weakening input (KEV) floats above a present one (model)"
    );
    let kev = &rows[kev_pos];
    assert_eq!(kev.state, InputStateProps::Absent);
    assert!(kev.weakens_decisions);
    // The enable instruction is present so the operator knows how to fix the gap.
    assert!(kev.enable.contains("PROTECTOR_KEV_FILE"));
}

#[test]
fn a_degraded_model_reads_degraded_not_absent_or_present() {
    let r = derive_readiness(
        &covered(),
        ModelHealth::Timeout,
        &BakeStats::default(),
        Some(SystemTime::now()),
    );
    let rows = map_readiness(&r);
    let model = rows.iter().find(|row| row.id == "model").unwrap();
    assert_eq!(model.state, InputStateProps::Degraded);
    assert!(!model.state.is_present());
}

#[test]
fn arm_state_is_present_and_never_weakens() {
    let r = derive_readiness(
        &covered(),
        ModelHealth::Ok,
        &BakeStats::default(),
        Some(SystemTime::now()),
    );
    let rows = map_readiness(&r);
    let arm = rows.iter().find(|row| row.id == "arm-state").unwrap();
    assert_eq!(arm.state, InputStateProps::Present);
    assert!(!arm.weakens_decisions);
    // Arm-state is a posture toggle, not an input to enable, so it carries no env var.
    assert!(arm.enable.is_empty());
}
