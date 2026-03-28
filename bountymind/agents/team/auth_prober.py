import asyncio
import re
import time
import httpx
from .base_agent import BaseTeamAgent, AgentState, _build_raw_finding, _utcnow
from ...core.models import AgentLoadOut
from ...tools.scope_checker import validate_scope, ScopeViolationError


class AuthProber(BaseTeamAgent):
    agent_id    = "AuthProber"
    model_alias = "MODEL_AGENT_STD"

    async def _execute_node(self, state: AgentState) -> dict:
        loadout   = AgentLoadOut(**state["loadout"])
        test_idx  = state.get("test_idx", 0)
        iteration = state.get("iteration", 0)
        scope_rules = state.get("scope_rules", {})

        if test_idx >= len(loadout.test_cases) or iteration >= loadout.max_iterations:
            return {"messages": [{"role":"system","content":f"[AuthProber] done","agent":self.agent_id,"ts":_utcnow()}]}

        tc      = loadout.test_cases[test_idx]
        surface = tc.get("surface","")

        try:
            validate_scope(surface, scope_rules)
        except ScopeViolationError:
            return {"test_idx": test_idx+1, "iteration": iteration+1,
                    "messages":[{"role":"system","content":f"[AuthProber] scope skip","agent":self.agent_id,"ts":_utcnow()}]}

        technique   = tc.get("technique","")
        tool_config = loadout.tool_configs.get(technique, {})

        result = await self._run_auth_technique(technique, surface, tool_config, tc)

        findings = list(state.get("local_findings", []))
        if result.get("confirmed") or result.get("output"):
            findings.append(_build_raw_finding(tc, result, self.agent_id))

        should_collab = len(findings) > 0 and iteration > 0 and iteration % 3 == 0

        return {
            "local_findings": findings,
            "test_idx":       test_idx + 1,
            "iteration":      iteration + 1,
            "_should_collaborate": should_collab,
            "messages": [{"role":"system","content":f"[AuthProber] {technique} → {'✓' if result.get('confirmed') else '·'}","agent":self.agent_id,"ts":_utcnow()}],
        }

    async def _run_auth_technique(self, technique: str, surface: str, config: dict, tc: dict) -> dict:
        if technique == "timing_attack":
            return await self._timing_attack(surface, config)
        if technique == "reset_token_analysis":
            return await self._reset_token_analysis(surface, config)
        if technique == "oauth_redirect_uri":
            return await self._oauth_redirect_uri(surface, config)
        if technique == "user_enumeration":
            return await self._user_enumeration(surface, config)
        if technique == "session_fixation":
            return await self._session_fixation(surface, config)
        if technique == "brute_force_check":
            return await self._brute_force_check(surface, config)
        return {"confirmed": False, "output": ""}

    async def _timing_attack(self, url: str, config: dict) -> dict:
        real_user  = config.get("real_user",  "admin@example.com")
        fake_user  = config.get("fake_user",  "nonexistent_xyz@fakefake.xyz")
        field      = config.get("field",      "email")
        samples    = config.get("samples",    5)

        timings_real = []
        timings_fake = []

        try:
            async with httpx.AsyncClient(timeout=15, verify=False, follow_redirects=True) as client:
                for _ in range(samples):
                    t0 = time.monotonic()
                    await client.post(url, data={field: real_user, "password": "wrongpass"},
                                      headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0"})
                    timings_real.append((time.monotonic() - t0) * 1000)
                    await asyncio.sleep(0.15)

                for _ in range(samples):
                    t0 = time.monotonic()
                    await client.post(url, data={field: fake_user, "password": "wrongpass"},
                                      headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0"})
                    timings_fake.append((time.monotonic() - t0) * 1000)
                    await asyncio.sleep(0.15)

            avg_real = sum(timings_real) / len(timings_real)
            avg_fake = sum(timings_fake) / len(timings_fake)
            diff     = abs(avg_real - avg_fake)

            if diff > 100:
                return {
                    "confirmed":   True,
                    "output":      f"Timing difference {diff:.0f}ms between existing/non-existing users",
                    "description": f"User enumeration via timing attack: {diff:.0f}ms difference at {url}",
                    "request":     {"url": url, "field": field, "samples": samples},
                    "response_diff": {"avg_real_ms": round(avg_real), "avg_fake_ms": round(avg_fake), "diff_ms": round(diff)},
                    "payload":     f"{field}={real_user} vs {field}={fake_user}",
                    "reproduction_steps": [
                        f"1. POST to {url} with {field}=<real_user>",
                        f"2. POST to {url} with {field}=<fake_user>",
                        f"3. Measure response time difference ({diff:.0f}ms detected)",
                        "4. Difference > 100ms confirms user enumeration",
                    ],
                }
        except Exception:
            pass
        return {"confirmed": False, "output": ""}

    async def _reset_token_analysis(self, url: str, config: dict) -> dict:
        email = config.get("email", "test@test.com")
        tokens = []

        try:
            async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
                for _ in range(3):
                    resp = await client.post(url, data={"email": email},
                                             headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0"})
                    token_match = re.search(r'token[=:\s]+([a-zA-Z0-9_\-]{8,})', resp.text, re.I)
                    if token_match:
                        tokens.append(token_match.group(1))
                    await asyncio.sleep(0.3)

            if len(tokens) >= 2:
                entropy_ok = all(len(t) >= 32 for t in tokens)
                sequential = _are_sequential(tokens)
                if not entropy_ok or sequential:
                    return {
                        "confirmed":   True,
                        "output":      f"Reset tokens appear weak: {'sequential' if sequential else 'low entropy'}",
                        "description": f"Predictable password reset tokens at {url}",
                        "request":     {"url": url, "email": email},
                        "response_diff": {"tokens_sampled": len(tokens), "sequential": sequential, "low_entropy": not entropy_ok},
                        "payload":     email,
                        "reproduction_steps": [
                            f"1. Request 3+ password resets for {email} at {url}",
                            "2. Collect tokens from response/email",
                            "3. Analyze entropy and sequential patterns",
                        ],
                    }
        except Exception:
            pass
        return {"confirmed": False, "output": ""}

    async def _oauth_redirect_uri(self, url: str, config: dict) -> dict:
        evil_redirect = "https://evil.example.com/callback"
        try:
            async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=False) as client:
                test_url = f"{url}?redirect_uri={evil_redirect}&response_type=code&client_id=test"
                resp = await client.get(test_url, headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0"})
                if resp.status_code in (301, 302):
                    location = resp.headers.get("location", "")
                    if "evil.example.com" in location:
                        return {
                            "confirmed":   True,
                            "output":      f"OAuth redirect_uri accepted: {evil_redirect}",
                            "description": f"OAuth redirect_uri misconfiguration at {url}",
                            "request":     {"url": test_url},
                            "response_diff": {"location": location},
                            "payload":     f"redirect_uri={evil_redirect}",
                            "reproduction_steps": [
                                f"1. Navigate to {test_url}",
                                "2. Observe redirect to attacker-controlled URL",
                                "3. Authorization code / token leaked via Referer or redirect",
                            ],
                        }
        except Exception:
            pass
        return {"confirmed": False, "output": ""}

    async def _user_enumeration(self, url: str, config: dict) -> dict:
        real_user = config.get("real_user", "admin")
        fake_user = config.get("fake_user", "nonexistent_xyz_abc_123")
        field     = config.get("field", "email")

        try:
            async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
                resp_real = await client.post(url, data={field: real_user, "password": "wrongpassword"},
                                              headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0"})
                await asyncio.sleep(0.2)
                resp_fake = await client.post(url, data={field: fake_user, "password": "wrongpassword"},
                                              headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0"})

                if resp_real.text[:500] != resp_fake.text[:500] or resp_real.status_code != resp_fake.status_code:
                    return {
                        "confirmed":   True,
                        "output":      "Different responses for existing vs non-existing users",
                        "description": f"User enumeration via response difference at {url}",
                        "request":     {"url": url, "field": field},
                        "response_diff": {
                            "real_status": resp_real.status_code,
                            "fake_status": resp_fake.status_code,
                            "content_different": resp_real.text[:100] != resp_fake.text[:100],
                        },
                        "payload":     f"{field}={real_user} vs {field}={fake_user}",
                        "reproduction_steps": [
                            f"1. POST {url} with {field}=<valid>",
                            f"2. POST {url} with {field}=<invalid>",
                            "3. Compare responses — different content confirms enumeration",
                        ],
                    }
        except Exception:
            pass
        return {"confirmed": False, "output": ""}

    async def _session_fixation(self, url: str, config: dict) -> dict:
        try:
            async with httpx.AsyncClient(timeout=8, verify=False, follow_redirects=True) as client:
                resp1 = await client.get(url, headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0"})
                pre_cookies = dict(resp1.cookies)

                resp2 = await client.post(
                    url,
                    data={"username": "test@test.com", "password": "test"},
                    cookies=pre_cookies,
                    headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0"},
                )
                post_cookies = dict(resp2.cookies)

                if pre_cookies and pre_cookies == post_cookies and resp2.status_code in (200, 302):
                    return {
                        "confirmed":   True,
                        "output":      "Session ID not rotated after authentication",
                        "description": f"Session fixation vulnerability at {url}",
                        "request":     {"url": url},
                        "response_diff": {"session_rotated": False},
                        "payload":     str(pre_cookies),
                        "reproduction_steps": [
                            f"1. Obtain session ID from {url} before login",
                            "2. Authenticate with the same session ID",
                            "3. Confirm session ID unchanged post-authentication",
                        ],
                    }
        except Exception:
            pass
        return {"confirmed": False, "output": ""}

    async def _brute_force_check(self, url: str, config: dict) -> dict:
        attempts = config.get("attempts", 10)
        try:
            async with httpx.AsyncClient(timeout=5, verify=False, follow_redirects=True) as client:
                statuses = []
                for i in range(attempts):
                    resp = await client.post(
                        url,
                        data={"username": "test@test.com", "password": f"wrongpassword{i}"},
                        headers={"User-Agent": "Mozilla/5.0 BountyMind/4.0"},
                    )
                    statuses.append(resp.status_code)
                    if resp.status_code == 429:
                        break
                    await asyncio.sleep(0.1)

                if 429 not in statuses:
                    return {
                        "confirmed":   True,
                        "output":      f"No rate limiting detected after {len(statuses)} login attempts",
                        "description": f"Brute force protection absent at {url}",
                        "request":     {"url": url, "attempts": len(statuses)},
                        "response_diff": {"rate_limited": False, "attempts_before_block": None},
                        "payload":     "Multiple incorrect passwords",
                        "reproduction_steps": [
                            f"1. Send {attempts} POST requests to {url} with wrong passwords",
                            "2. No 429 or lockout response detected",
                            "3. Account can be brute-forced",
                        ],
                    }
        except Exception:
            pass
        return {"confirmed": False, "output": ""}


def _are_sequential(tokens: list[str]) -> bool:
    if len(tokens) < 2:
        return False
    try:
        nums = [int(t, 16) for t in tokens]
        diffs = [nums[i+1] - nums[i] for i in range(len(nums)-1)]
        return len(set(diffs)) == 1
    except ValueError:
        pass
    try:
        nums = [int(t) for t in tokens if t.isdigit()]
        if len(nums) == len(tokens):
            diffs = [nums[i+1] - nums[i] for i in range(len(nums)-1)]
            return len(set(diffs)) == 1
    except Exception:
        pass
    return False
