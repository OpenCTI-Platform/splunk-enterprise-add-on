import requests

from utils import get_proxy_config
from constants import VERIFY_SSL


class SplunkAppConnectorHelper:
    def __init__(
        self, connector_id, connector_name, opencti_url, opencti_api_key, splunk_helper
    ):
        self.connector_id = connector_id
        self.connector_name = connector_name
        self.opencti_url = opencti_url
        self.splunk_helper = splunk_helper
        self.headers = {
            "Authorization": "Bearer " + opencti_api_key,
        }
        self.api_url = self.opencti_url + "/graphql"

        # manage SSL verification
        splunk_helper.log_debug(f"verify SSL: {VERIFY_SSL}")

        # manage proxies configuration
        self.proxies = get_proxy_config(splunk_helper)

    def graphql_query(self, query, variables=None):
        body = {
            "query": query,
            "variables": variables or {},
        }

        r = requests.post(
            url=self.api_url,
            json=body,
            headers=self.headers,
            verify=VERIFY_SSL,
            proxies=self.proxies,
        )

        if r.status_code != 200:
            self.splunk_helper.log_error(
                f"OpenCTI GraphQL HTTP error {r.status_code}: {r.text}"
            )
            raise Exception(f"OpenCTI GraphQL HTTP {r.status_code}: {r.content}")

        data = r.json()
        if "errors" in data:
            self.splunk_helper.log_error(f"OpenCTI GraphQL errors: {data['errors']}")
            raise Exception(f"OpenCTI GraphQL errors: {data['errors']}")

        return data.get("data", {})

    def get_indicator_relations(self, indicator_id, max_edges=50):
        query = """
        query IndicatorEnrichment($id: String!, $first: Int) {
          indicator(id: $id) {
            id
            name
            confidence
            x_opencti_score
            x_opencti_main_observable_type
            stixCoreRelationships(first: $first) {
              edges {
                node {
                  id
                  relationship_type
                  to {
                    ... on AttackPattern {
                      entity_type
                      name
                      x_mitre_id
                    }
                    ... on Malware {
                      entity_type
                      name
                    }
                    ... on ThreatActor {
                      entity_type
                      name
                    }
                    ... on StixCyberObservable {
                      entity_type
                      observable_value
                    }
                  }
                }
              }
            }
          }
        }
        """
        data = self.graphql_query(query, {"id": indicator_id, "first": max_edges})
        indicator = data.get("indicator") or {}
        rels = indicator.get("stixCoreRelationships") or {}
        return rels.get("edges") or []

    def get_indicator_enrichment(self, indicator_id, max_edges=50):
        """
        Flatten related objects into simple lists by type.
        """
        edges = self.get_indicator_relations(indicator_id, max_edges=max_edges)
        if not edges:
            return None

        def _names_by_type(target_type):
            names = []
            for edge in edges:
                node = edge.get("node") or {}
                to_ = node.get("to") or {}
                if to_.get("entity_type") == target_type and to_.get("name"):
                    names.append(to_["name"])
            return sorted(set(names))

        return {
            "attack_patterns": _names_by_type("Attack-Pattern"),
            "malware": _names_by_type("Malware"),
            "threat_actors": _names_by_type("Threat-Actor"),
        }

    def register(self):
        """
        :return:
        """
        input = {
            "input": {
                "id": self.connector_id,
                "name": self.connector_name,
                "type": "STREAM",
                "scope": "",
                "auto": False,
                "only_contextual": False,
                "playbook_compatible": False,
            }
        }

        query = """
            mutation RegisterConnector($input: RegisterConnectorInput) {
                registerConnector(input: $input) {
                    id
                    connector_state
                    config {
                        connection {
                            host
                            vhost
                            use_ssl
                            port
                            user
                            pass
                        }
                        listen
                        listen_routing
                        listen_exchange
                        push
                        push_routing
                        push_exchange
                    }
                    connector_user_id
                }
            }
        """

        r = requests.post(
            url=self.api_url,
            json={"query": query, "variables": input},
            headers=self.headers,
            verify=VERIFY_SSL,
            proxies=self.proxies,
        )

        if r.status_code != 200:
            raise Exception(
                f"An exception occurred while registering Splunk App, "
                f"received status code: {r.status_code}, exception: {r.content}"
            )

    def send_stix_bundle(self, bundle):
        """
        :param bundle:
        :return:
        """
        query = """
            mutation stixBundle($id: String!, $bundle: String!) {
                stixBundlePush(connectorId: $id, bundle: $bundle)
            }
        """

        variables = {"id": self.connector_id, "bundle": bundle}

        r = requests.post(
            url=self.api_url,
            json={"query": query, "variables": variables},
            headers=self.headers,
            verify=VERIFY_SSL,
            proxies=self.proxies,
        )
        if r.status_code != 200:
            raise Exception(
                f"An exception occurred while sending STIX bundle, "
                f"received status code: {r.status_code}, exception: {r.content}"
            )
