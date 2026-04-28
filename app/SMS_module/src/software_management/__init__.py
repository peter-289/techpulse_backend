def create_sms_app(*args, **kwargs):
    from .bootstrap import create_sms_app as _create_sms_app

    return _create_sms_app(*args, **kwargs)


__all__ = ["create_sms_app"]
