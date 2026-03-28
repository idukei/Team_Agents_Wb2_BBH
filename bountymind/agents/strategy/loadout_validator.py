from ...core.models import AgentLoadOut
from ...tools.registry import ToolRegistry


def validate_loadout(loadout: AgentLoadOut, surface_inventory: dict) -> dict:
    errors   = []
    warnings = []

    if not loadout.active:
        return {"valid": True, "errors": [], "warnings": []}

    known_urls = {ep["url"] for ep in surface_inventory.get("endpoints", [])}
    known_urls.update(f["action"] for f in surface_inventory.get("forms", []))
    known_urls.update(f["url"]    for f in surface_inventory.get("forms", []))

    for tc in loadout.test_cases:
        surface = tc.get("surface", "")
        if surface and surface not in known_urls:
            if not any(surface.startswith(url.rsplit("/", 1)[0]) for url in known_urls):
                warnings.append(f"test_case surface '{surface}' not found in surface_inventory")

    all_tools  = ToolRegistry.list_all()
    known_tool_names = set(all_tools.keys()) if isinstance(all_tools, dict) else set()
    for tool in loadout.tools:
        if known_tool_names and tool not in known_tool_names:
            warnings.append(f"tool '{tool}' not registered in ToolRegistry")

    if loadout.max_iterations > 50:
        errors.append("max_iterations > 50 requires HITL approval (HITL-5)")

    if not loadout.test_cases:
        errors.append("active loadout has no test_cases")

    if not loadout.mission:
        errors.append("mission is required for active loadout")

    if not loadout.methodology:
        warnings.append("methodology is empty — agent will have no step structure")

    for tc in loadout.test_cases:
        if not tc.get("technique"):
            errors.append(f"test_case missing 'technique': {tc}")

    return {
        "valid":    len(errors) == 0,
        "errors":   errors,
        "warnings": warnings,
    }


def validate_all_loadouts(loadouts: dict, surface_inventory: dict) -> dict:
    results = {}
    for agent_id, loadout_dict in loadouts.items():
        try:
            loadout = AgentLoadOut(**loadout_dict)
            results[agent_id] = validate_loadout(loadout, surface_inventory)
        except Exception as e:
            results[agent_id] = {"valid": False, "errors": [str(e)], "warnings": []}
    return results
