from .views import ExpenseSummaryStats,IncomeSummaryStats
from django.urls import path

urlpatterns = [
    path('expense-category-data',ExpenseSummaryStats.as_view(),name="expense-category-summary"),
    path('income-source-data',IncomeSummaryStats.as_view(),name="income-source-data")

]