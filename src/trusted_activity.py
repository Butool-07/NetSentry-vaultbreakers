
from datetime import datetime
from load_config import load_config


def is_trusted_activity(source_ip, activity_type, timestamp=None):
    """Check whether activity matches configured trusted settings."""
    settings = load_config()
    rules = settings["trusted_activity_rules"]

    # Ignore configured approved scanners for the three detection rules.
    if (
        activity_type in (
            "port_scan",
            "network_sweep",
            "lateral_movement",
        )
        and rules["ignore_approved_scanners"]
        and source_ip in settings["approved_scanners"]
    ):
        return True

    # Ignore configured patch-server sources for these detection rules.
    if (
        activity_type in (
            "port_scan",
            "network_sweep",
            "lateral_movement",
        )
        and rules["ignore_patch_server_sources"]
        and source_ip in settings["patch_servers"]
    ):
        return True

    # Allow backups during the configured schedule.
    if activity_type == "backup" and rules["allow_scheduled_backups"]:
        if timestamp is not None:
            hour = datetime.fromisoformat(str(timestamp)).hour
            start = settings["backup_schedule"]["start_hour"]
            end = settings["backup_schedule"]["end_hour"]

            if start <= hour < end:
                return True

    # Allow maintenance during the configured schedule.
    if (
        activity_type == "maintenance"
        and rules["allow_scheduled_maintenance"]
    ):
        if timestamp is not None:
            hour = datetime.fromisoformat(str(timestamp)).hour
            start = settings["maintenance_schedule"]["start_hour"]
            end = settings["maintenance_schedule"]["end_hour"]

            if start <= hour < end:
                return True

    return False


if __name__ == "__main__":
    print(
        "Approved scanner test:",
        is_trusted_activity("192.168.1.20", "port_scan"),
    )
    print(
        "Unknown source test:",
        is_trusted_activity("192.168.1.50", "port_scan"),
    )
