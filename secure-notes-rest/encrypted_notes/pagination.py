from django.conf import settings

from rest_framework.pagination import PageNumberPagination


class DefaultPagination(PageNumberPagination):
    page_size = settings.ENCRYPTED_NOTES['DEFAULT_PAGE_SIZE']
    max_page_size = settings.ENCRYPTED_NOTES['MAX_PAGE_SIZE']
    page_size_query_param = settings.ENCRYPTED_NOTES['PAGE_SIZE_PARAM']
