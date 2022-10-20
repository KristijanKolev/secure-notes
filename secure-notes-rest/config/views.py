from django.http import HttpResponseBadRequest, HttpResponseNotFound, HttpResponseServerError
import json


def error400(request, exception):
    response_data = {
        'detail': 'Bad request.'
    }
    return HttpResponseBadRequest(json.dumps(response_data), content_type="application/json")


def error404(request, exception):
    response_data = {
        'detail': 'Not found.'
    }
    return HttpResponseNotFound(json.dumps(response_data), content_type="application/json")


def error500(request):
    response_data = {
        'detail': 'Internal server error.'
    }
    return HttpResponseServerError(json.dumps(response_data), content_type="application/json")

