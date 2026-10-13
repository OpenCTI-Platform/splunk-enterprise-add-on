import requests
import utils
from typing import Union


class GraphQLError(Exception):
    """OpenCTI answered HTTP 200 with GraphQL errors."""


class SplunkAppConnectorHelper:
    def __init__(
        self,
        connector_id,
        connector_name,
        opencti_url,
        opencti_api_key,
        proxy_settings,
        verify: Union[bool, str] = True,
        user_agent=None,
    ):
        """
        :param connector_id:
        :param connector_name:
        :param opencti_url:
        :param opencti_api_key:
        :param proxy_settings:
        :param verify:
            Value to pass as ``verify=`` to requests
            (True, False, or CA bundle path).
        :param user_agent:
            Value of the ``User-Agent`` header (see utils.get_user_agent);
            requests' default is kept when None.
        """
        self.connector_id = connector_id
        self.connector_name = connector_name
        self.opencti_url = opencti_url
        self.headers = {
            "Authorization": "Bearer " + opencti_api_key,
        }
        if user_agent:
            self.headers["User-Agent"] = user_agent
        self.api_url = self.opencti_url + "/graphql"
        self.proxies = utils.get_proxy_config(proxy_settings=proxy_settings)
        self.verify = verify

    def graphql_query(self, query, variables=None):
        """
        :param query:
        :param variables:
        :return:
        """
        body = {
            "query": query,
            "variables": variables or {},
        }

        r = requests.post(
            url=self.api_url,
            json=body,
            headers=self.headers,
            verify=self.verify,
            proxies=self.proxies,
        )

        if r.status_code != 200:
            raise Exception(
                f"OpenCTI GraphQL HTTP {r.status_code}: {r.content}"
            )

        data = r.json()
        if "errors" in data:
            raise GraphQLError(f"OpenCTI GraphQL errors: {data['errors']}")

        return data.get("data", {})

    def get_indicator_relations(self, indicator_id, max_edges=50):
        """
        :param indicator_id:
        :param max_edges:
        :return:
        """
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
                    ... on Vulnerability {
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
        data = self.graphql_query(
            query,
            {"id": indicator_id, "first": max_edges}
        )
        indicator = data.get("indicator") or {}
        rels = indicator.get("stixCoreRelationships") or {}
        return rels.get("edges") or []

    def get_indicator_enrichment(self, indicator_id, max_edges=50):
        """
        latten related objects into simple lists by type.
        :param indicator_id:
        :param max_edges:
        :return:
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
            "vulnerabilities": _names_by_type("Vulnerability"),
        }

    def register(self):
        """
        Register the Splunk App as an OpenCTI connector (create or update).
        :return:
        """
        variables = {
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
                }
            }
        """
        self.graphql_query(query, variables)

    def ping(self):
        """
        Declare the connector as run by an external schedule: OpenCTI shows
        "Next run: External schedule". Best effort, connector_info exists
        since OpenCTI 6.2.12.
        :return:
        """
        variables = {
            "id": self.connector_id,
            "connectorInfo": {
                "run_and_terminate": True,
                "buffering": False,
                "queue_threshold": 500,
                "queue_messages_size": 0,
            },
        }
        query = """
            mutation PingConnector($id: ID!, $connectorInfo: ConnectorInfoInput) {
                pingConnector(id: $id, connectorInfo: $connectorInfo) {
                    id
                }
            }
        """
        try:
            self.graphql_query(query, variables)
        except Exception:
            pass

    def _push_stix_bundle(self, bundle):
        """
        :param bundle:
        :return:
        """
        query = """
            mutation stixBundle($id: String!, $bundle: String!) {
                stixBundlePush(connectorId: $id, bundle: $bundle)
            }
        """
        self.graphql_query(query, {"id": self.connector_id, "bundle": bundle})

    def send_stix_bundle(self, bundle):
        """
        Push a STIX bundle. The Splunk App is registered only when needed:
        if OpenCTI rejects the push (connector not registered yet, or
        deleted in OpenCTI), the App registers and pushes again, once.
        HTTP and network errors are raised without retry, so a bundle is
        never pushed twice.
        :param bundle:
        :return: True if the App was registered during this push
        """
        try:
            self._push_stix_bundle(bundle)
            return False
        except GraphQLError as push_error:
            try:
                self.register()
            except Exception:
                raise push_error
            self.ping()
            self._push_stix_bundle(bundle)
            return True
