import argparse
import json
import os
import sys

import environ
from django.core.management.base import BaseCommand
from django.db import DEFAULT_DB_ALIAS, ConnectionHandler
from ...models import User


class Command(BaseCommand):
    help = "Migrates users from a previous installation's database"

    def add_arguments(self, parser):
        parser.add_argument(
            "database_url",
            help="Database URL to migrate users from.",
            type=str,
        )
        parser.add_argument(
            "--osm-passwords",
            default=None,
            help="Output JSON file with email keys and OSM passwords values.",
            type=argparse.FileType("w"),
        )
        parser.add_argument(
            "--osm-passwords-indent",
            default=None,
            help="Indentation for OSM passwords output JSON.",
            type=int,
        )

    def handle(self, database_url, **options):
        # Retrieve legacy django.contrib.auth User entries from the
        # given database url.
        db_info = environ.Env.db_url_config(database_url)
        if not db_info:
            sys.stderr.write("Cannot parse the database url.\n")
            sys.exit(os.EX_USAGE)
        conn_h = ConnectionHandler({DEFAULT_DB_ALIAS: db_info})
        conn = conn_h.create_connection(DEFAULT_DB_ALIAS)
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT email, password FROM auth_user")
                auth_users = cursor.fetchall()
        except Exception as exc:
            sys.stderr.write(f"Database error: {exc.args}\n")
            sys.exit(os.EX_DATAERR)

        # Create or update the users email/password values.
        for email, password in auth_users:
            user, created = User.objects.update_or_create(
                {"password": password}, email=email
            )
            if created:
                sys.stderr.write(f"created: {user}\n")
            else:
                sys.stderr.write(f"updated: {user}\n")

        # When requested, also dump OSM passwords for synchronization.
        if options["osm_passwords"]:
            options["osm_passwords"].write(
                json.dumps(
                    dict(
                        (email, osm_password)
                        for email, osm_password in User.objects.values_list(
                            "email", "osm_password"
                        )
                    ),
                    indent=options["osm_passwords_indent"],
                )
            )
