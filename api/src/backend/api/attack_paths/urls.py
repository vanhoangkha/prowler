from django.urls import path

from api.attack_paths.views_toxic_combinations import (
    list_toxic_combinations,
    compute_score,
)

urlpatterns = [
    path("toxic-combinations/", list_toxic_combinations, name="toxic-combinations-list"),
    path("score/", compute_score, name="attack-paths-score"),
]
