# src/app/cli/privana_cli.py

import click
from ..core.protection import PrivanaProtection
from ..core.endpoint_check import EndpointChecker

@click.group()
def cli():
    """Privana: Your Private Road on the Internet"""
    pass

@cli.command()
@click.option('--config', default=None, help='Path to configuration file')
def connect(config):
    """Connect to Privana VPN"""
    # Check endpoint integrity
    checker = EndpointChecker()
    if not checker.check():
        click.echo("Endpoint integrity check failed. Aborting connection.")
        return
    
    # Initialize protection
    protection = PrivanaProtection(config)
    try:
        protection.connect()
        click.echo("Connected to Privana. Your internet is now private.")
    except Exception as e:
        click.echo(f"Failed to connect: {str(e)}")

@cli.command()
def disconnect():
    """Disconnect from Privana VPN"""
    protection = PrivanaProtection()
    try:
        protection.disconnect()
        click.echo("Disconnected from Privana.")
    except Exception as e:
        click.echo(f"Failed to disconnect: {str(e)}")

@cli.command()
def status():
    """Check connection status"""
    protection = PrivanaProtection()
    if protection.is_connected():
        click.echo("Status: Protected")
    else:
        click.echo("Status: Unprotected")

if __name__ == '__main__':
    cli()