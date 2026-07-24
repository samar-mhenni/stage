from simple_crew.workflows import run_red_team, run_threat_intel


def get_red_team_runner():
    return run_red_team


def get_threat_intel_runner():
    return run_threat_intel

