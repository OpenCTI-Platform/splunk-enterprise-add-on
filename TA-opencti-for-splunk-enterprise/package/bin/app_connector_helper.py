import requests
import utils
from typing import Union

# Seconds before an OpenCTI GraphQL call is abandoned (connect, read).
GRAPHQL_TIMEOUT = (10, 120)


class OpenCTIGraphQLError(Exception):
    """An OpenCTI GraphQL call failed at the HTTP or at the GraphQL level."""

    def __init__(self, message, errors=None, status_code=None):
        super().__init__(message)
        self.errors = errors or []
        self.status_code = status_code

    def messages(self):
        """
        :return: the messages of the GraphQL errors (empty for HTTP failures)
        """
        return [
            str(error.get("message", "")) if isinstance(error, dict) else str(error)
            for error in self.errors
        ]

    def mentions(self, text):
        """
        :param text: case-insensitive fragment
        :return: True when the error or one of its GraphQL messages contains text
        """
        needle = text.lower()
        if needle in str(self).lower():
            return True
        return any(needle in message.lower() for message in self.messages())


class SplunkAppConnectorHelper:
    # Connectors already registered by this process, keyed by (url, connector id):
    # alert actions handle every result of a search in one process.
    _registered = set()

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
        self.opencti_url = (opencti_url or "").rstrip("/")
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
        Run a GraphQL operation and fail on HTTP and GraphQL errors alike.

        OpenCTI answers HTTP 200 with an "errors" member for permission,
        validation and business errors, so the status code alone never proves
        success (#19).

        :param query:
        :param variables:
        :return: the "data" member of the response
        :raise OpenCTIGraphQLError:
        """
        body = {
            "query": query,
            "variables": variables or {},
        }

        try:
            r = requests.post(
                url=self.api_url,
                json=body,
                headers=self.headers,
                verify=self.verify,
                proxies=self.proxies,
                timeout=GRAPHQL_TIMEOUT,
            )
        except requests.RequestException as ex:
            raise OpenCTIGraphQLError(f"OpenCTI GraphQL request failed: {ex}") from ex

        if r.status_code != 200:
            raise OpenCTIGraphQLError(
                f"OpenCTI GraphQL HTTP {r.status_code}: {r.content}",
                status_code=r.status_code,
            )

        try:
            data = r.json()
        except ValueError as ex:
            raise OpenCTIGraphQLError(
                f"OpenCTI GraphQL returned a non-JSON response: {r.content[:500]}",
                status_code=r.status_code,
            ) from ex
        if not isinstance(data, dict):
            raise OpenCTIGraphQLError(f"OpenCTI GraphQL returned an unexpected payload: {data!r}")
        if data.get("errors"):
            raise OpenCTIGraphQLError(
                f"OpenCTI GraphQL errors: {data['errors']}",
                errors=data["errors"],
                status_code=r.status_code,
            )

        return data.get("data") or {}

    def get_indicator_relations(self, indicator_id, max_edges=50, extra_fields=""):
        """
        :param indicator_id:
        :param max_edges:
        :param extra_fields: additional Indicator fields to select (feature
            detected by the caller, see opencti_features)
        :return: (relationship edges, indicator node)
        """
        query = """
        query IndicatorEnrichment($id: String!, $first: Int) {
          indicator(id: $id) {
            id
            name
            confidence
            x_opencti_score
            x_opencti_main_observable_type
            %s
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
        """ % extra_fields
        data = self.graphql_query(
            query,
            {"id": indicator_id, "first": max_edges}
        )
        indicator = data.get("indicator") or {}
        rels = indicator.get("stixCoreRelationships") or {}
        return rels.get("edges") or [], indicator

    def get_indicator_enrichment(self, indicator_id, max_edges=50, extra_fields=""):
        """
        Flatten related objects into simple lists by type.
        :param indicator_id:
        :param max_edges:
        :param extra_fields: see get_indicator_relations
        :return: dict of lists by type plus "indicator" (the raw node, used for
            the provenance and pulse fields), or None when nothing was found
        """
        edges, indicator = self.get_indicator_relations(
            indicator_id, max_edges=max_edges, extra_fields=extra_fields
        )
        if not edges and not indicator:
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
            "indicator": indicator,
        }

    def register(self):
        """
        Register the app as an OpenCTI connector, once per process.
        :return: the registered connector
        :raise OpenCTIGraphQLError:
        """
        registration_key = (self.api_url, self.connector_id)
        if registration_key in SplunkAppConnectorHelper._registered:
            return None
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
                    connector_state
                    connector_user_id
                }
            }
        """
        data = self.graphql_query(query, variables)
        connector = data.get("registerConnector")
        if not connector:
            raise OpenCTIGraphQLError(
                "OpenCTI did not return the registered connector "
                f"(response: {data!r})"
            )
        SplunkAppConnectorHelper._registered.add(registration_key)
        return connector

    def send_stix_bundle(self, bundle):
        """
        :param bundle: serialized STIX 2.1 bundle
        :return: the stixBundlePush result
        :raise OpenCTIGraphQLError:
        """
        query = """
            mutation stixBundle($id: String!, $bundle: String!) {
                stixBundlePush(connectorId: $id, bundle: $bundle)
            }
        """

        variables = {"id": self.connector_id, "bundle": bundle}
        data = self.graphql_query(query, variables)
        if "stixBundlePush" not in data:
            raise OpenCTIGraphQLError(
                f"OpenCTI did not acknowledge the STIX bundle (response: {data!r})"
            )
        return data.get("stixBundlePush")
