import requests
import datetime
from dateutil import parser
from requests.auth import HTTPBasicAuth

# CONFIGURATION
SONARQUBE_URL = "https://your-sonarqube-instance.com"
AUTH_TOKEN = "your_sonar_token"  # Use empty string "" if public access
MONTHS_THRESHOLD = 6

# HEADERS and AUTH
headers = {'Accept': 'application/json'}
auth = HTTPBasicAuth(AUTH_TOKEN, '') if AUTH_TOKEN else None

# Time threshold
now = datetime.datetime.utcnow()
cutoff_date = now - datetime.timedelta(days=30 * MONTHS_THRESHOLD)

def get_projects():
    """Fetch all projects from SonarQube"""
    projects = []
    page = 1

    while True:
        response = requests.get(
            f"{SONARQUBE_URL}/api/projects/search",
            params={"p": page, "ps": 100},
            headers=headers,
            auth=auth
        )
        data = response.json()
        projects.extend(data.get('components', []))
        if page * 100 >= data.get('paging', {}).get('total', 0):
            break
        page += 1

    return projects

def get_last_analysis(project_key, branch=None, pull_request=None):
    """Fetch last analysis date for a given branch or PR"""
    url = f"{SONARQUBE_URL}/api/project_analyses/search"
    params = {"project": project_key}
    if branch:
        params["branch"] = branch
    if pull_request:
        params["pullRequest"] = pull_request

    response = requests.get(url, params=params, headers=headers, auth=auth)
    data = response.json()
    analyses = data.get("analyses", [])

    if not analyses:
        return None

    return parser.parse(analyses[0]['date'])

def get_branches(project_key):
    """Fetch branches and PRs for a project"""
    response = requests.get(
        f"{SONARQUBE_URL}/api/project_branches/list",
        params={"project": project_key},
        headers=headers,
        auth=auth
    )
    return response.json().get("branches", [])

def main():
    projects = get_projects()
    inactive_projects = []

    for project in projects:
        project_key = project["key"]
        branches = get_branches(project_key)

        main_inactive = True
        pr_inactive = True

        for branch in branches:
            name = branch["name"]
            is_pr = branch.get("isPullRequest", False)

            last_analysis = get_last_analysis(
                project_key,
                branch=None if is_pr else name,
                pull_request=name if is_pr else None
            )

            if last_analysis:
                if last_analysis >= cutoff_date:
                    if is_pr:
                        pr_inactive = False
                    else:
                        main_inactive = False

        if main_inactive and pr_inactive:
            inactive_projects.append(project_key)

    print(f"Inactive projects (no analysis in last {MONTHS_THRESHOLD} months on both main and PR branches):")
    for project_key in inactive_projects:
        print(f"- {project_key}")

if __name__ == "__main__":
    main()
