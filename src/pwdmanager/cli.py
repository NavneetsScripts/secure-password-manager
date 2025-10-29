from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from .vault import Vault, VaultError, AuthError


def _default_vault_dir(args: argparse.Namespace) -> Path:
    return Path(args.vault_dir) if getattr(args, "vault_dir", None) else Path("vault")


def cmd_init(args: argparse.Namespace) -> int:
    v = Vault(_default_vault_dir(args))
    master = getpass.getpass("Create master password: ")
    confirm = getpass.getpass("Confirm master password: ")
    if master != confirm:
        print("Passwords do not match", file=sys.stderr)
        return 1
    try:
        v.init_vault(master)
        print(f"Initialized vault at {v.base_dir}")
        return 0
    except VaultError as e:
        print(str(e), file=sys.stderr)
        return 1


def _require_master_and_load(args: argparse.Namespace) -> Vault | None:
    v = Vault(_default_vault_dir(args))
    master = getpass.getpass("Master password: ")
    try:
        v.load(master)
        return v
    except AuthError:
        print("Invalid master password", file=sys.stderr)
        return None
    except VaultError as e:
        print(str(e), file=sys.stderr)
        return None


def cmd_add(args: argparse.Namespace) -> int:
    v = _require_master_and_load(args)
    if v is None:
        return 1
    password = getpass.getpass("Entry password (input hidden): ")
    try:
        v.add(args.name, args.username, password, overwrite=args.overwrite)
        print(f"Added entry '{args.name}'")
        return 0
    except VaultError as e:
        print(str(e), file=sys.stderr)
        return 1


def cmd_get(args: argparse.Namespace) -> int:
    v = _require_master_and_load(args)
    if v is None:
        return 1
    try:
        item = v.get(args.name)
        print(f"Username: {item['username']}")
        if args.show:
            print(f"Password: {item['password']}")
        else:
            print("Password: [hidden] (use --show to display)")
        return 0
    except VaultError as e:
        print(str(e), file=sys.stderr)
        return 1


def cmd_update(args: argparse.Namespace) -> int:
    v = _require_master_and_load(args)
    if v is None:
        return 1
    password = None
    if args.prompt_password:
        password = getpass.getpass("New entry password (input hidden): ")
    try:
        v.update(args.name, username=args.username, password=password)
        print(f"Updated '{args.name}'")
        return 0
    except VaultError as e:
        print(str(e), file=sys.stderr)
        return 1


def cmd_delete(args: argparse.Namespace) -> int:
    v = _require_master_and_load(args)
    if v is None:
        return 1
    try:
        v.delete(args.name)
        print(f"Deleted '{args.name}'")
        return 0
    except VaultError as e:
        print(str(e), file=sys.stderr)
        return 1


def cmd_list(args: argparse.Namespace) -> int:
    v = _require_master_and_load(args)
    if v is None:
        return 1
    for name in v.list_names():
        print(name)
    return 0


def cmd_change_master(args: argparse.Namespace) -> int:
    v = Vault(_default_vault_dir(args))
    old_master = getpass.getpass("Current master password: ")
    new_master = getpass.getpass("New master password: ")
    confirm = getpass.getpass("Confirm new master password: ")
    if new_master != confirm:
        print("Passwords do not match", file=sys.stderr)
        return 1
    try:
        v.change_master(old_master, new_master)
        print("Master password updated")
        return 0
    except AuthError:
        print("Invalid master password", file=sys.stderr)
        return 1
    except VaultError as e:
        print(str(e), file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pwdman", description="Secure password manager")
    p.add_argument("--vault-dir", help="Path to vault directory (default: ./vault)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("init", help="Initialize a new vault")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("add", help="Add a new credential")
    sp.add_argument("--name", required=True)
    sp.add_argument("--username", required=True)
    sp.add_argument("--overwrite", action="store_true", help="Overwrite if entry exists")
    sp.set_defaults(func=cmd_add)

    sp = sub.add_parser("get", help="Get a credential")
    sp.add_argument("--name", required=True)
    sp.add_argument("--show", action="store_true", help="Print password to stdout (use with care)")
    sp.set_defaults(func=cmd_get)

    sp = sub.add_parser("update", help="Update a credential")
    sp.add_argument("--name", required=True)
    sp.add_argument("--username")
    sp.add_argument("--prompt-password", action="store_true", help="Prompt for new password")
    sp.set_defaults(func=cmd_update)

    sp = sub.add_parser("delete", help="Delete a credential")
    sp.add_argument("--name", required=True)
    sp.set_defaults(func=cmd_delete)

    sp = sub.add_parser("list", help="List entry names")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("change-master", help="Change master password")
    sp.set_defaults(func=cmd_change_master)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
