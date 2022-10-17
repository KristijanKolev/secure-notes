from rest_framework import permissions


class IsCreatorOrReadOnly(permissions.BasePermission):
    """
    Custom permissions to allow only the creator of an object to perform certain actions.
    """

    def has_object_permission(self, request, view, obj):
        return request.method in permissions.SAFE_METHODS or obj.creator == request.user
