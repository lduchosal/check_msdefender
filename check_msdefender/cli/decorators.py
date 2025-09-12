"""CLI decorators for check_msdefender."""

import click


def common_options(func):
    """Decorator for common CLI options."""
    func = click.option('-c', '--config', default='check_msdefender.ini', help='Configuration file path')(func)
    func = click.option('-v', '--verbose', count=True, help='Increase verbosity')(func)
    func = click.option('-m', '--machine-id', help='Machine ID (GUID)')(func)
    func = click.option('-d', '--dns-name', help='Computer DNS Name (FQDN)')(func)
    func = click.option('-W', '--warning', type=float, help='Warning threshold')(func)
    func = click.option('-C', '--critical', type=float, help='Critical threshold')(func)

    return func