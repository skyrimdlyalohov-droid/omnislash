#!/usr/bin/env python3
"""Canonical negative WAF-stub responses for native brain calibration.

These templates are deliberately inert: every record is labeled negative and
carries both feature tags and JSONL ``tags`` that the self-learning ingester
enforces. They can therefore never be promoted into a confirmed finding by
feature aggregation or by a later audit merge.

Stdlib only; no sockets, no Docker, no external network.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

try:
    from research.semantic_analyzer import classify_response_shape
    from research.self_learning import TrainingExample, feature_key
except ImportError:  # pragma: no cover - direct script execution
    from semantic_analyzer import classify_response_shape  # type: ignore
    from self_learning import TrainingExample, feature_key  # type: ignore


BASELINE_RESPONSE: Dict[str, Any] = {
    "status": 200,
    "headers": [{"key": "server", "value": "lab-backend"}],
    "body": "<html><body><h1>Lab</h1><p>ok</p></body></html>",
}

# (name, vendor, status, headers, body, forced-negative tags)
WAF_STUB_TEMPLATES: Tuple[Tuple[str, str, int, Tuple[Tuple[str, str], ...], str, Tuple[str, ...]], ...] = (
    (
        "cloudflare",
        "cloudflare",
        403,
        (
            ("Server", "cloudflare"),
            ("Cf-Ray", "8f3a2b1c9d0e4f5a-SIN"),
            ("Content-Type", "text/html; charset=UTF-8"),
            ("X-Frame-Options", "SAMEORIGIN"),
        ),
        "<!DOCTYPE html><html><head><title>Attention Required! | Cloudflare</title></head>"
        "<body><h1>Attention Required!</h1><p>Sorry, you have been blocked. "
        "You are unable to access this site.</p><p>Ray ID: 8f3a2b1c9d0e4f5a-SIN</p></body></html>",
        ("negative", "negative-template", "waf-stub"),
    ),
    (
        "akamai",
        "akamai",
        403,
        (
            ("Server", "AkamaiGHost"),
            ("x-akamai-transaction", "4000000:0:stub"),
            ("Content-Type", "text/html"),
        ),
        "<HTML><HEAD><TITLE>Access Denied</TITLE></HEAD><BODY>"
        "<H1>Access Denied</H1>You don't have permission to access this server.<BR>"
        "Reference #18.stub.1774000000.0</BODY></HTML>",
        ("negative", "negative-template", "waf-stub"),
    ),
    (
        "aws-waf",
        "aws-waf",
        403,
        (
            ("Server", "Amazon"),
            ("x-amzn-RequestId", "stub-request-id"),
            ("Content-Type", "text/html; charset=utf-8"),
        ),
        "<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body>"
        "<h1>403 Forbidden</h1><p>Request blocked by AWS WAF.</p></body></html>",
        ("negative", "negative-template", "waf-stub"),
    ),
    (
        "qrator",
        "qrator",
        403,
        (
            ("Server", "qrator"),
            ("X-Qrator-Rule", "102"),
            ("Content-Type", "text/html; charset=utf-8"),
        ),
        "<html><head><title>403 Forbidden</title></head><body>"
        "<h1>Access denied</h1><p>Request rejected by Qrator filter.</p></body></html>",
        ("negative", "negative-template", "waf-stub"),
    ),
    (
        "nginx",
        "nginx",
        403,
        (
            ("Server", "nginx"),
            ("Content-Type", "text/html"),
        ),
        "<html><head><title>403 Forbidden</title></head><body><center>"
        "<h1>403 Forbidden</h1></center><hr><center>nginx</center></body></html>",
        ("negative", "negative-template", "waf-stub"),
    ),
    (
        "clean-noise",
        "none",
        200,
        (
            ("Server", "lab-backend"),
            ("Content-Type", "text/html; charset=utf-8"),
        ),
        "<!DOCTYPE html><html><head><title>Lab service</title></head>"
        "<body><h1>Lab service</h1><p>Nothing to see here.</p></body></html>",
        ("negative", "negative-template", "clean-noise"),
    ),
    (
        "route-miss-noise",
        "none",
        404,
        (
            ("Server", "lab-backend"),
            ("Content-Type", "text/html; charset=utf-8"),
        ),
        "<html><head><title>Not Found</title></head><body><h1>404 Not Found</h1>"
        "<p>The requested path does not exist.</p></body></html>",
        ("negative", "negative-template", "clean-noise"),
    ),
)


def response_for_template(template: Tuple[Any, ...]) -> Dict[str, Any]:
    """Return a semantic-analyzer-compatible response dict for a template."""
    _name, _vendor, status, headers, body, _tags = template
    return {
        "status": status,
        "headers": [{"key": key, "value": value} for key, value in headers],
        "body": body,
    }


def waf_negative_jsonl_records(host_prefix: str = "native-pair-waf") -> List[Dict[str, Any]]:
    """Build forced-negative, TrainingExample-compatible JSONL records."""
    records: List[Dict[str, Any]] = []
    for template in WAF_STUB_TEMPLATES:
        name, vendor, status, _headers, _body, tags = template
        response = response_for_template(template)
        shape = classify_response_shape(
            response, role="victim", target_host="stub.invalid", baseline=BASELINE_RESPONSE
        )
        is_waf = vendor != "none"
        reason = "waf_stub" if is_waf else "clean_noise"
        features: Dict[str, str] = {
            "probe": "waf-stub-template",
            "tls": "h1",
            "shape": shape.shape.value,
            "status:" + str(status): "1",
            "waf_template:" + name: "1",
            "negative_reason": reason,
            "confirmed_finding": "0",
            "not_finding": "1",
            "enforced_negative": "1",
        }
        if is_waf:
            features[feature_key("waf_vendor", vendor)] = "1"
        else:
            features[feature_key("noise_kind", name)] = "1"
        example = TrainingExample(
            host="%s-%s" % (host_prefix, name),
            tech="waf" if is_waf else "clean",
            features=features,
            label=0.0,
            source="native-pair:waf-negative-template",
            confidence=1.0,
        )
        record = example.as_dict()
        record["tags"] = list(tags)
        record["metadata"] = {
            "template": name,
            "vendor": vendor,
            "response": response,
            "enforced_negative": True,
        }
        records.append(record)
    return records


def build_waf_negative_examples(host_prefix: str = "native-pair-waf") -> List[TrainingExample]:
    """Convenience wrapper returning TrainingExample objects."""
    return [TrainingExample.from_dict(record) for record in waf_negative_jsonl_records(host_prefix)]


__all__ = [
    "BASELINE_RESPONSE",
    "WAF_STUB_TEMPLATES",
    "build_waf_negative_examples",
    "response_for_template",
    "waf_negative_jsonl_records",
]
