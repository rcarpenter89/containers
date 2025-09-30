import requests
from requests.auth import HTTPBasicAuth
import urllib3
import json
import os
import csv
import logging
import time
# Suppress only the single InsecureRequestWarning from urllib3 needed for development.
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
from datetime import datetime

# Suppress only the single InsecureRequestWarning from urllib3 needed for development.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Replace with your actual org_id, API key, and token
api_user = "api_191fd6f8a4487b920"
api_key = "c14080fd65c49b9818748be21f2661423d27aed6a2514fcf8bb8229123b2f6e5"
fqdn = "us-scp14.illum.io"
port = "443"
org = "3801148"

# List of container cluster IDs to query (from enforcement script)
container_cluster_ids = [
    "972af9b8-bd91-40d8-92cf-f193ab7d55b1",
    "ccf01471-c4ba-4c1b-b27c-58c260e11e5a", 
    "c5a60da8-ce75-4d93-905d-5baa2f9e5831",
    "b6e20aa2-019e-4f6a-9294-148263bd2cb2",
    "a4ab6a4e-23e2-46f2-a917-229798cf4898",
    "fe2406a0-cbe9-419f-b896-9aaab9a12996",
    "586fb1bd-486b-4f51-a812-801db96fe679",
    "6dcee2b1-ea2a-4fdd-803c-8ec801be2949",
    "943c22dd-3b59-458e-aee3-d48d5f6bb6f4",
    "1eb0ef16-31d8-4df2-8438-9617bd84314d",
    "30adce45-925d-47fb-a200-1edc121e59e1",
    "0d9c2a24-f4ce-442d-938b-91e81b7ac406",
    "c7747396-62d0-4697-aea2-d35d403c3e7f",
    "0c96caba-c5b9-4c39-bef3-a7f601dcb8cd",
    "f0d466f8-80d5-4c71-a331-bac3ee02bbad",
    "bc111ee1-b133-4353-8a70-580b00e34678",
    "1a54d7f0-4bb6-41a7-b27b-800fae2de43c",
    "8c27d1bf-68bb-4202-ae58-7b6ecd306ba5",
    "f516893a-4426-4c20-860b-a857c2900bb8"
]

def get_path(filename):
    return os.path.join(os.path.dirname(__file__), filename)

def get_workloads(org_id, api_user, api_key, container_cluster_uris):
    url = f"https://{fqdn}:{port}/api/v2/orgs/{org_id}/workloads"
    headers = {
        'Accept': 'application/json',
    }
    limit = 1000
    offset = 0
    all_workloads = []
    total = None
    while True:
        params = {
            'container_clusters': json.dumps(container_cluster_uris),
            'limit': limit,
            'offset': offset
        }
        logging.info(f"Requesting workloads: offset={offset}, limit={limit}")
        response = requests.get(url, verify=False, headers=headers, auth=HTTPBasicAuth(api_user, api_key), params=params)
        logging.info(f"Status code: {response.status_code}")
        if response.status_code == 200:
            data = response.json()
            # Handle both list and dict response
            if isinstance(data, dict) and 'items' in data:
                items = data['items']
                total = data.get('total', None)
                logging.info(f"Retrieved {len(items)} workloads on this page (dict response). Total: {total}")
            else:
                items = data if isinstance(data, list) else []
                logging.info(f"Retrieved {len(items)} workloads on this page (list response).")
            if not items:
                break
            all_workloads.extend(items)
            if len(items) < limit:
                break
            offset += limit
        else:
            logging.error(f"Error: Unable to fetch container workloads. Status code: {response.status_code}")
            break
    logging.info(f"Total container workloads retrieved: {len(all_workloads)} (API total: {total})")
    return all_workloads

def get_kubernetes_workloads(org_id, api_user, api_key, container_cluster_uris):
    url = f"https://{fqdn}:{port}/api/v2/orgs/{org_id}/kubernetes_workloads"
    headers = {
        'Accept': 'application/json',
    }
    limit = 500  # Illumio API may have a max page size of 500 for kubernetes workloads
    offset = 0
    all_workloads = []
    total = None
    max_retries = 5
    retry_delay = 3  # seconds
    max_items = 28000  # Set this to your known max number of kubernetes workloads
    while True:
        params = {
            'container_clusters': json.dumps(container_cluster_uris),
            'limit': limit,
            'offset': offset
        }
        logging.info(f"Requesting kubernetes workloads: offset={offset}, limit={limit}")
        for attempt in range(max_retries):
            try:
                response = requests.get(url, verify=False, headers=headers, auth=HTTPBasicAuth(api_user, api_key), params=params)
                logging.info(f"Status code: {response.status_code}")
                break
            except requests.exceptions.SSLError as e:
                logging.warning(f"SSLError on attempt {attempt+1}/{max_retries}: {e}")
                time.sleep(retry_delay)
        else:
            logging.error(f"Max retries exceeded for offset={offset}. Skipping this page.")
            break
        if response.status_code == 200:
            data = response.json()
            # Handle both list and dict response
            if isinstance(data, dict) and 'items' in data:
                items = data['items']
                total = data.get('total', None)
                logging.info(f"Retrieved {len(items)} kubernetes workloads on this page (dict response). Total: {total}")
            else:
                items = data if isinstance(data, list) else []
                logging.info(f"Retrieved {len(items)} kubernetes workloads on this page (list response).")
            if not items:
                logging.info("No items returned, breaking pagination loop.")
                break
            all_workloads.extend(items)
            # If less than limit returned, this is the last page
            if len(items) < limit:
                logging.info("Last page reached (less than limit returned), breaking pagination loop.")
                break
            # Stop if we've reached the total number of objects (if known)
            if total is not None and len(all_workloads) >= total:
                logging.info(f"Reached total kubernetes workloads: {len(all_workloads)} (API total: {total})")
                break
            # Stop if we've reached the hard max
            if len(all_workloads) >= max_items:
                logging.info(f"Reached hard max kubernetes workloads: {len(all_workloads)}")
                break
            offset += limit
            time.sleep(retry_delay)
        else:
            logging.error(f"Error: Unable to fetch kubernetes workloads. Status code: {response.status_code}")
            break
    logging.info(f"Total kubernetes workloads retrieved: {len(all_workloads)} (API total: {total})")
    return all_workloads

def flatten_labels(labels):
    if not labels:
        return ""
    flat = []
    for label in labels:
        if isinstance(label, dict):
            key = label.get('key')
            value = label.get('value')
            if key and value:
                flat.append(f"{key}: {value}")
            elif key:
                flat.append(key)
            elif value:
                flat.append(value)
            assignment = label.get('assignment')
            if assignment and 'value' in assignment:
                flat.append(f"{key}: {assignment['value']}")
    return "; ".join(flat)

def main():
    container_cluster_uris = [f"/orgs/{org}/container_clusters/{cid}" for cid in container_cluster_ids]
    # Get container workloads
    container_workloads = get_workloads(org, api_user, api_key, container_cluster_uris)
    # Get kubernetes workloads
    k8s_workloads = get_kubernetes_workloads(org, api_user, api_key, container_cluster_uris)
    logging.info(f"Final count - container workloads: {len(container_workloads)}, kubernetes workloads: {len(k8s_workloads)}")
    # Write to CSV
    csv_path = get_path('all_workloads_labels_enforcement.csv')
    with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            'Type', 'Cluster Name', 'Workload Name', 'Namespace', 'Kind', 'Enforcement Mode', 'Sync State', 'Labels', 'Profile Enforcement', 'Profile Labels', 'Policy Applied', 'Heartbeat'
        ])
        # Container workloads
        for w in container_workloads:
            cluster_name = w.get('container_cluster', {}).get('name', '')
            name = w.get('hostname', '')
            namespace = w.get('namespace', '')
            kind = w.get('kind', '')
            enforcement_mode = w.get('enforcement_mode', '')
            sync_state = w.get('agent', {}).get('status', {}).get('security_policy_sync_state', '')
            labels = flatten_labels(w.get('labels', []))
            profile = w.get('container_workload_profile', {})
            profile_enforcement = profile.get('enforcement_mode', '')
            profile_labels = flatten_labels(profile.get('labels', []))
            policy_applied = w.get('agent', {}).get('status', {}).get('security_policy_applied_at', '')
            heartbeat = w.get('agent', {}).get('status', {}).get('last_heartbeat_at', '')
            writer.writerow([
                'container', cluster_name, name, namespace, kind, enforcement_mode, sync_state, labels, profile_enforcement, profile_labels, policy_applied, heartbeat
            ])
        # Kubernetes workloads
        for w in k8s_workloads:
            cluster_name = w.get('container_cluster', {}).get('name', '')
            name = w.get('name', '')
            namespace = w.get('namespace', '')
            kind = w.get('kind', '')
            enforcement_mode = w.get('enforcement_mode', '')
            sync_state = w.get('security_policy_sync_state', '')
            labels = flatten_labels(w.get('labels', []))
            profile = w.get('container_workload_profile', {})
            profile_enforcement = profile.get('enforcement_mode', '')
            profile_labels = flatten_labels(profile.get('labels', []))
            policy_applied = w.get('security_policy_applied_at', '')
            heartbeat = w.get('last_heartbeat_at', '')
            writer.writerow([
                'kubernetes', cluster_name, name, namespace, kind, enforcement_mode, sync_state, labels, profile_enforcement, profile_labels, policy_applied, heartbeat
            ])
    print(f"Wrote all container and kubernetes workloads with labels and enforcement to {csv_path}")

if __name__ == "__main__":
    main()

