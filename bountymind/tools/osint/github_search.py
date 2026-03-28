import os
import httpx


GH_ADVISORY_URL = "https://api.github.com/graphql"
GH_TOKEN        = os.getenv("GITHUB_TOKEN", "")


async def github_advisory_search(package_name: str) -> list[dict]:
    if not GH_TOKEN:
        return []

    query = """
    query($pkg: String!) {
      securityVulnerabilities(first: 5, ecosystem: NPM, package: $pkg, orderBy: {field: UPDATED_AT, direction: DESC}) {
        nodes {
          advisory {
            ghsaId
            summary
            severity
            cvss { score vectorString }
            publishedAt
          }
          vulnerableVersionRange
          firstPatchedVersion { identifier }
        }
      }
    }
    """

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                GH_ADVISORY_URL,
                json={"query": query, "variables": {"pkg": package_name}},
                headers={
                    "Authorization": f"Bearer {GH_TOKEN}",
                    "Content-Type":  "application/json",
                },
            )
            if resp.status_code != 200:
                return []

            data  = resp.json()
            nodes = (data.get("data") or {}).get("securityVulnerabilities", {}).get("nodes", [])

            results = []
            for node in nodes:
                adv  = node.get("advisory", {})
                cvss = adv.get("cvss", {})
                results.append({
                    "id":          adv.get("ghsaId", ""),
                    "summary":     adv.get("summary", ""),
                    "severity":    adv.get("severity", ""),
                    "cvss_score":  cvss.get("score", 0),
                    "vector":      cvss.get("vectorString", ""),
                    "package":     package_name,
                    "vuln_range":  node.get("vulnerableVersionRange", ""),
                    "patched_in":  (node.get("firstPatchedVersion") or {}).get("identifier", ""),
                    "published":   adv.get("publishedAt", ""),
                })
            return results
    except Exception:
        return []
