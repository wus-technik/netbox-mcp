import json

import pytest
from fastmcp import Client
from mcp.shared.exceptions import MCPError

from netbox_mcp.tools.common import CONTENT_KEY_RENAME
from netbox_mcp.tools.common import rename_content_keys
from tests.conftest import build_server

ALL_TOOL_COUNT = 24  # with branching enabled


def key_paths(value, path=""):
    """Yield the path of every dict key in a JSON-like structure."""
    if isinstance(value, dict):
        for key, child in value.items():
            yield f"{path}/{key}"
            yield from key_paths(child, f"{path}/{key}")
    elif isinstance(value, list):
        for child in value:
            yield from key_paths(child, path)


def test_rename_content_keys_is_recursive():
    data = {
        "content": "a",
        "nested": [{"content": {"content": 1}, "other": 2}],
        "plain": "content",
    }
    assert rename_content_keys(data) == {
        CONTENT_KEY_RENAME: "a",
        "nested": [{CONTENT_KEY_RENAME: {CONTENT_KEY_RENAME: 1}, "other": 2}],
        "plain": "content",
    }


@pytest.mark.parametrize(
    "data",
    [
        {"content": "c", "content_value": "v"},
        {"content_value": "v", "content": "c"},
    ],
)
def test_rename_content_keys_keeps_both_values_on_collision(data):
    renamed = rename_content_keys({"nested": [data]})
    assert renamed == {"nested": [{"content": "c", "content_value": "v"}]}


def test_rename_content_keys_passes_scalars_and_lists_through():
    assert rename_content_keys([1, "x", None]) == [1, "x", None]
    assert rename_content_keys("content") == "content"


@pytest.fixture
def branching_config(config):
    config.branching_enabled = True
    return config


async def test_every_tool_has_title_annotations_and_object_output_schema(
    branching_config, netbox
):
    async with Client(build_server(branching_config, netbox.transport)) as client:
        tools = await client.list_tools()
    assert len(tools) == ALL_TOOL_COUNT
    for tool in tools:
        assert tool.title, tool.name
        auto_title = tool.name.replace("_", " ").title()
        assert tool.title != auto_title, tool.name
        assert tool.annotations is not None, tool.name
        schema = tool.output_schema
        assert schema is None or schema["type"] == "object", tool.name


async def test_list_tool_structured_content_is_object_and_text_unchanged(
    config, client_for, netbox
):
    netbox.get(
        "dcim/devices",
        payload={"count": 1, "next": None, "results": [{"id": 1, "name": "sw1"}]},
    )
    async with client_for(config) as client:
        result = await client.call_tool(
            "netbox_get_objects", {"object_type": "dcim.device"}
        )
    assert isinstance(result.structured_content, dict)
    assert result.structured_content["results"] == [{"id": 1, "name": "sw1"}]
    assert json.loads(result.content[0].text) == result.structured_content


async def test_content_key_is_renamed_in_structured_content_only(
    config, client_for, netbox
):
    netbox.post("dcim/devices/5/render-config", payload={"content": "hostname sw1"})
    async with client_for(config) as client:
        result = await client.call_tool(
            "netbox_render_config", {"object_type": "dcim.device", "object_id": 5}
        )
    assert result.structured_content == {CONTENT_KEY_RENAME: "hostname sw1"}
    assert "/content" not in set(key_paths(result.structured_content))
    # The text content keeps the data exactly as before.
    assert json.loads(result.content[0].text) == {"content": "hostname sw1"}


async def test_nested_content_key_is_renamed(config, client_for, netbox):
    netbox.get(
        "dcim/devices/1",
        payload={"id": 1, "custom_fields": {"note": {"content": "x"}}},
    )
    async with client_for(config) as client:
        result = await client.call_tool(
            "netbox_get_object", {"object_type": "dcim.device", "object_id": 1}
        )
    paths = set(key_paths(result.structured_content))
    assert not any(p.rsplit("/", 1)[-1] == "content" for p in paths)
    assert result.structured_content["custom_fields"]["note"] == {
        CONTENT_KEY_RENAME: "x"
    }


async def test_tool_error_is_is_error(config, client_for, netbox):
    netbox.get("dcim/devices/1", status=500, payload={"detail": "boom"})
    async with client_for(config) as client:
        result = await client.call_tool(
            "netbox_get_object",
            {"object_type": "dcim.device", "object_id": 1},
            raise_on_error=False,
        )
    assert result.is_error is True


async def test_unknown_tool_is_invalid_params(config, client_for):
    async with client_for(config) as client:
        with pytest.raises(MCPError) as excinfo:
            await client.call_tool_mcp("netbox_does_not_exist", {})
    assert excinfo.value.error.code == -32602
