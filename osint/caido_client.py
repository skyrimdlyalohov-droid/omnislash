#!/usr/bin/env python3
"""Minimal Caido GraphQL client for OmniSlash integration.

This module is intentionally defensive and dependency-free (stdlib only).
It supports:
- creating/selecting a project for a target scope,
- loading allowlist/denylist scope rules,
- exporting HTTPQL query results and findings into unified OmniSlash JSON.

Environment/config:
- CAIDO_URL (default: http://127.0.0.1:8080/graphql)
- CAIDO_PAT  (required for authenticated API access)
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional


class CaidoAPIError(RuntimeError):
    pass


@dataclass
class UnifiedFinding:
    source: str
    kind: str
    host: str
    path: str
    severity: str
    title: str
    request_id: str = ""
    evidence: Dict[str, Any] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if d.get("evidence") is None:
            d["evidence"] = {}
        return d


class CaidoClient:
    def __init__(self, url: Optional[str] = None, pat: Optional[str] = None, timeout: int = 30):
        self.url = url or os.environ.get("CAIDO_URL", "http://127.0.0.1:8080/graphql")
        self.pat = pat or os.environ.get("CAIDO_PAT", "")
        self.timeout = timeout

    def _headers(self) -> Dict[str, str]:
        h = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.pat:
            h["Authorization"] = f"Bearer {self.pat}"
        return h

    def graphql(self, query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        payload = {"query": query, "variables": variables or {}}
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(self.url, data=data, headers=self._headers(), method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise CaidoAPIError(f"HTTP {e.code}: {body[:500]}") from e
        except Exception as e:
            raise CaidoAPIError(str(e)) from e
        try:
            parsed = json.loads(body)
        except Exception as e:
            raise CaidoAPIError(f"invalid JSON response: {body[:500]}") from e
        if parsed.get("errors"):
            raise CaidoAPIError(json.dumps(parsed["errors"])[:1000])
        return parsed.get("data", parsed)

    # --- Project / scope management ---

    def create_project(self, name: str) -> Dict[str, Any]:
        """Create a Caido project. Schema names may vary across Caido versions;
        this method tries the common mutation shape and returns raw data."""
        query = """
        mutation CreateProject($name: String!) {
          createProject(input: {name: $name}) {
            project { id name }
            error { code message }
          }
        }
        """
        try:
            return self.graphql(query, {"name": name})
        except CaidoAPIError:
            # fallback generic shape
            query2 = """
            mutation($name:String!){
              projectCreate(input:{name:$name}){ project{id name} }
            }
            """
            return self.graphql(query2, {"name": name})

    def set_scope(self, project_id: str, allow_hosts: List[str], deny_hosts: Optional[List[str]] = None) -> Dict[str, Any]:
        """Load allow/deny scope. Uses a best-effort mutation shape; caller should
        verify against their Caido version."""
        deny_hosts = deny_hosts or []
        query = """
        mutation SetScope($projectId: ID!, $allow: [String!]!, $deny: [String!]!) {
          setScope(input: {projectId: $projectId, allowlist: $allow, denylist: $deny}) {
            success
            error { code message }
          }
        }
        """
        variables = {"projectId": project_id, "allow": allow_hosts, "deny": deny_hosts}
        try:
            return self.graphql(query, variables)
        except CaidoAPIError as e:
            return {"error": str(e), "note": "scope mutation shape may differ by Caido version; apply manually in UI"}

    # --- Export ---

    def export_httpql(self, httpql: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Export requests matching HTTPQL. Returns raw records; normalize with
        normalize_httpql_records()."""
        query = """
        query ExportHTTPQL($httpql: String!, $limit: Int!) {
          requestsByHTTPQL(httpql: $httpql, limit: $limit) {
            nodes {
              id
              host
              path
              method
              statusCode
              length
              raw
            }
          }
        }
        """
        try:
            data = self.graphql(query, {"httpql": httpql, "limit": limit})
        except CaidoAPIError:
            # alternative shape
            query2 = "query($q:String!){ search(httpql:$q){ id host path method status } }"
            data = self.graphql(query2, {"q": httpql})
        nodes = (
            data.get("requestsByHTTPQL", {}).get("nodes")
            or data.get("search")
            or data.get("requests")
            or []
        )
        if isinstance(nodes, dict):
            nodes = nodes.get("nodes", [])
        return list(nodes)

    def export_findings(self, limit: int = 200) -> List[Dict[str, Any]]:
        query = """
        query ExportFindings($limit: Int!) {
          findings(limit: $limit) {
            nodes {
              id
              title
              severity
              host
              path
              description
            }
          }
        }
        """
        try:
            data = self.graphql(query, {"limit": limit})
        except CaidoAPIError:
            data = self.graphql("query{ findings{ id title severity host path } }")
        nodes = data.get("findings", {}).get("nodes") or data.get("findings") or []
        if isinstance(nodes, dict):
            nodes = nodes.get("nodes", [])
        return list(nodes)

    def export_unified(self, httpql: str = "", limit: int = 200) -> Dict[str, Any]:
        findings = []
        for f in self.export_findings(limit=limit):
            findings.append(UnifiedFinding(
                source="caido",
                kind="finding",
                host=str(f.get("host", "")),
                path=str(f.get("path", "")),
                severity=str(f.get("severity", "info")).lower(),
                title=str(f.get("title", "")),
                request_id=str(f.get("id", "")),
                evidence={k: v for k, v in f.items() if k not in {"id", "title", "severity", "host", "path"}},
            ).to_dict())
        requests = self.export_httpql(httpql, limit=limit) if httpql else []
        return {
            "source": "caido",
            "httpql": httpql,
            "findings": findings,
            "requests": requests,
        }


def write_unified_report(path: str, report: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
        f.write("\n")


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description="Caido GraphQL export for OmniSlash")
    ap.add_argument("--url", default=os.environ.get("CAIDO_URL", "http://127.0.0.1:8080/graphql"))
    ap.add_argument("--pat", default=os.environ.get("CAIDO_PAT", ""))
    ap.add_argument("--project", default="", help="project name to create")
    ap.add_argument("--httpql", default="", help="HTTPQL query to export")
    ap.add_argument("--out", default="/tmp/omnislash_caido_export.json")
    ap.add_argument("--limit", type=int, default=200)
    args = ap.parse_args(argv)

    c = CaidoClient(url=args.url, pat=args.pat)
    if args.project:
        print(json.dumps(c.create_project(args.project), indent=2, ensure_ascii=False))
    report = c.export_unified(httpql=args.httpql, limit=args.limit)
    write_unified_report(args.out, report)
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()