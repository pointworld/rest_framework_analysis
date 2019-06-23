# Django REST Framework 源码解析


## 目录结构

```text
.
├── __init__.py
├── apps.py
├── authentication.py
├── authtoken
│   ├── __init__.py
│   ├── admin.py
│   ├── apps.py
│   ├── management
│   │   ├── __init__.py
│   │   └── commands
│   ├── migrations
│   ├── models.py
│   ├── serializers.py
│   └── views.py
├── checks.py
├── compat.py
├── decorators.py
├── documentation.py
├── exceptions.py
├── fields.py
├── filters.py
├── generics.py
├── locale
├── management
│   ├── __init__.py
│   └── commands
│       ├── __init__.py
│       └── generateschema.py
├── metadata.py
├── mixins.py
├── negotiation.py
├── pagination.py
├── parsers.py
├── permissions.py
├── relations.py
├── renderers.py
├── request.py
├── response.py
├── reverse.py
├── routers.py
├── schemas
│   ├── __init__.py
│   ├── generators.py
│   ├── inspectors.py
│   ├── utils.py
│   └── views.py
├── serializers.py
├── settings.py
├── static
│   └── rest_framework
│       ├── css
│       ├── docs
│       ├── fonts
│       ├── img
│       └── js
├── status.py
├── templates
│   └── rest_framework
├── templatetags
│   ├── __init__.py
│   └── rest_framework.py
├── test.py
├── throttling.py
├── urlpatterns.py
├── urls.py
├── utils
│   ├── __init__.py
│   ├── breadcrumbs.py
│   ├── encoders.py
│   ├── field_mapping.py
│   ├── formatting.py
│   ├── html.py
│   ├── humanize_datetime.py
│   ├── json.py
│   ├── mediatypes.py
│   ├── model_meta.py
│   ├── representation.py
│   ├── serializer_helpers.py
│   └── urls.py
├── validators.py
├── versioning.py
├── views.py
└── viewsets.py
```
