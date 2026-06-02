import pytest
import yaml

from peat.consts import lower_dict
from peat.data import DeviceData
from peat.settings import Configuration


@pytest.fixture
def yml_config(examples_path) -> dict:
    return yaml.safe_load(examples_path("peat-config.yaml").read_text())


def _non_credential_keys(keys) -> list:
    """
    Drop credential settings (``*_user`` / ``*_password``) from a set of keys.

    These intentionally live only in ``examples/peat-credentials.example.yaml``
    (kept out of source control), not the main config examples, so they are
    excluded from the example-config key-match checks below.
    """
    return sorted(k for k in keys if not (k.endswith("_user") or k.endswith("_password")))


def test_example_yaml_config_matches_settings(yml_config):
    conf = Configuration("configuration", env_prefix="TEST_CONF_", init_env=False)
    exported = lower_dict(conf.json_dict(include_none_vals=True))
    assert _non_credential_keys(exported) == _non_credential_keys(yml_config)


def test_device_options_defaults(yml_config, deep_compare):
    deep_compare(
        DeviceData().options.to_dict(),
        yml_config["device_options"],
        exclude_regexes=r"\['(user|pass|users|passwords|creds|pull_delay|ec)'\]",
    )


def test_simple_example_yaml_config_matches_settings(examples_path):
    conf = Configuration("configuration", env_prefix="TEST_CONF_", init_env=False)
    exported = lower_dict(conf.json_dict(include_none_vals=True))
    yml_config = yaml.safe_load(examples_path("peat-config-simple.yaml").read_text())
    assert _non_credential_keys(exported) == _non_credential_keys(yml_config)
