"""``soerm asset add | show | list | update``."""

import argparse

from soerm.cli.common import (
    mutation_parent,
    open_workspace,
    print_mutation,
    read_parent,
)
from soerm.cli.output import dumps_json, render_key_values, render_table, write_line
from soerm.cli.parser import SafeArgumentParser
from soerm.domain.asset import Asset
from soerm.domain.enums import BusinessCriticality, DataClassification, Environment, Exposure
from soerm.services import assets as asset_service

__all__ = ["asset_to_dict", "register"]


def asset_to_dict(asset: Asset) -> dict[str, object]:
    """Stable field order, shared by ``show`` and ``list``."""
    return {
        "asset_id": asset.asset_id,
        "hash": asset.digest(),
        "name": asset.name,
        "owner": asset.owner,
        "environment": asset.environment.value,
        "business_criticality": asset.business_criticality.value,
        "data_classification": asset.data_classification.value,
        "exposure": asset.exposure.value,
        "tags": list(asset.tags),
        "created_at": asset.created_at.isoformat().replace("+00:00", "Z"),
        "updated_at": asset.updated_at.isoformat().replace("+00:00", "Z"),
    }


def _add(args: argparse.Namespace) -> int:
    result = asset_service.create_asset(
        open_workspace(args),
        actor=args.actor,
        name=args.name,
        owner=args.owner,
        environment=args.environment,
        business_criticality=args.criticality,
        data_classification=args.classification,
        exposure=args.exposure,
        tags=args.tag or (),
    )
    return print_mutation(result, verb="created", as_json=args.json)


def _show(args: argparse.Namespace) -> int:
    data = asset_to_dict(asset_service.get_asset(open_workspace(args), args.asset_id))
    if args.json:
        write_line(dumps_json(data))
    else:
        data["tags"] = ", ".join(str(tag) for tag in data["tags"])  # type: ignore[attr-defined]
        write_line(render_key_values(list(data.items())))
    return 0


def _list(args: argparse.Namespace) -> int:
    assets = asset_service.list_assets(
        open_workspace(args), environment=args.environment, sort=args.sort
    )
    if args.json:
        write_line(dumps_json({"assets": [asset_to_dict(a) for a in assets]}))
        return 0
    rows = [
        (a.asset_id, a.name, a.owner, a.environment, a.business_criticality, a.exposure)
        for a in assets
    ]
    write_line(
        render_table(("ID", "NAME", "OWNER", "ENVIRONMENT", "CRITICALITY", "EXPOSURE"), rows)
    )
    return 0


def _update(args: argparse.Namespace) -> int:
    result = asset_service.update_asset(
        open_workspace(args),
        args.asset_id,
        actor=args.actor,
        expected_hash=args.expect_hash,
        name=args.name,
        owner=args.owner,
        environment=args.environment,
        business_criticality=args.criticality,
        data_classification=args.classification,
        exposure=args.exposure,
        tags=() if args.clear_tags else args.tag,
    )
    return print_mutation(result, verb="updated", as_json=args.json)


def _fields(parser: argparse.ArgumentParser, *, required: bool) -> None:
    parser.add_argument("--name", required=required, metavar="TEXT")
    parser.add_argument("--owner", required=required, metavar="TEXT")
    parser.add_argument(
        "--environment", required=required, type=Environment, choices=list(Environment)
    )
    parser.add_argument(
        "--criticality",
        required=required,
        type=BusinessCriticality,
        choices=list(BusinessCriticality),
    )
    parser.add_argument(
        "--classification",
        required=required,
        type=DataClassification,
        choices=list(DataClassification),
    )
    parser.add_argument("--exposure", required=required, type=Exposure, choices=list(Exposure))


def register(subparsers: "argparse._SubParsersAction[SafeArgumentParser]") -> None:
    asset = subparsers.add_parser("asset", help="manage assets", description="Manage assets.")
    commands = asset.add_subparsers(
        dest="asset_command", required=True, parser_class=SafeArgumentParser
    )
    add = commands.add_parser(
        "add", parents=[mutation_parent()], help="create an asset", description="Create an asset."
    )
    _fields(add, required=True)
    add.add_argument("--tag", action="append", metavar="TAG", help="repeatable")
    add.set_defaults(handler=_add)

    show = commands.add_parser(
        "show", parents=[read_parent()], help="show an asset", description="Show an asset."
    )
    show.add_argument("asset_id", metavar="ASSET_ID")
    show.set_defaults(handler=_show)

    list_parser = commands.add_parser(
        "list", parents=[read_parent()], help="list assets", description="List assets."
    )
    list_parser.add_argument("--environment", type=Environment, choices=list(Environment))
    list_parser.add_argument(
        "--sort",
        type=asset_service.AssetSort,
        choices=list(asset_service.AssetSort),
        default=asset_service.AssetSort.ID,
    )
    list_parser.set_defaults(handler=_list)

    update = commands.add_parser(
        "update",
        parents=[mutation_parent()],
        help="change an asset",
        description="Change an asset. The hash shown by 'asset show' is required: "
        "the update is refused with 'conflict' if the asset changed since.",
    )
    update.add_argument("asset_id", metavar="ASSET_ID")
    update.add_argument(
        "--expect-hash", required=True, metavar="SHA256", help="'hash' printed by 'asset show'"
    )
    _fields(update, required=False)
    tags = update.add_mutually_exclusive_group()
    tags.add_argument("--tag", action="append", metavar="TAG", help="repeatable; replaces all tags")
    tags.add_argument("--clear-tags", action="store_true", help="remove all tags")
    update.set_defaults(handler=_update)
