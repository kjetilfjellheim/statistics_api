use std::sync::Arc;

use sqlx::{Pool, Postgres};
use tracing::{instrument, Instrument};

use crate::{
    dao::statistics::StatisticsDao,
    model::{
        apperror::{ApplicationError, ErrorType},
        models::{MunicipalityAddInputType, MunicipalityListOutputType, PaginationInput, StatisticAddInputType, StatisticsListOutputType, ValuesAddUpdateInputType, ValuesListInputType, ValuesListOutputType},
    },
};

/**
 * Represents the service for managing statistics.
 */
pub struct StatisticsService {
    /**
     * The DAO for statistics operations.
     */
    statistics_dao: StatisticsDao,
    /**
     * Optional connection pool for database operations. Optional for test purposes until we have a better way to mock the database.
     */
    connection_pool: Option<Arc<Pool<Postgres>>>,
}

impl StatisticsService {

    /**
     * Creates a new instance of `StatisticsService`.
     *
     * # Arguments
     * `statistics_dao`: The DAO for statistics operations.
     * `connection_pool`: Optional connection pool for database operations.
     *
     * # Returns
     * A new instance of `StatisticsService`.
     */
    pub fn new(statistics_dao: StatisticsDao, connection_pool: Option<Arc<Pool<Postgres>>>) -> Self {
        StatisticsService { statistics_dao, connection_pool }
    }

    /**
     * Retrieves a list of municipalities based on the provided pagination input.
     *
     * # Arguments
     * `pagination_input`: `PaginationInput` containing pagination information.
     *
     * # Returns
     * A Result containing `MunicipalityListOutputType` or an `ApplicationError`.
     */
    #[instrument(skip(self))]
    pub async fn get_municipality_list(&self, pagination_input: PaginationInput) -> Result<MunicipalityListOutputType, ApplicationError> {
        let span = tracing::Span::current();
        let Some(connection_pool) = &self.connection_pool else { 
            return Err(ApplicationError::new(ErrorType::DatabaseError, "No database connection available".to_string())) 
        };
        self.statistics_dao.get_municipality_list(connection_pool, pagination_input).instrument(span).await
    }

    /**
     * Adds a new municipality.
     *
     * # Arguments
     * `municipality_add_input`: The input type containing the details of the municipality to be added.
     *
     * # Returns
     * A Result indicating success or an `ApplicationError`.
     */
    #[instrument(skip(self))]
    pub async fn add_municipality(&self, municipality_add_input: MunicipalityAddInputType) -> Result<(), ApplicationError> {
        let span: tracing::Span = tracing::Span::current();
        let Some(connection_pool) = &self.connection_pool else { 
            return Err(ApplicationError::new(ErrorType::DatabaseError, "No database connection available".to_string())) 
        };
        let mut transaction = connection_pool.begin().instrument(span.clone()).await.map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to begin transaction: {err}")))?;
        match self.statistics_dao.add_municipality(&mut transaction, municipality_add_input).instrument(span.clone()).await {
            Ok(()) => transaction.commit().await.map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to commit transaction: {err}")))?,
            Err(err) => {
                transaction.rollback().await.map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to rollback transaction: {err}")))?;
                return Err(err);
            }
        }
        Ok(())
    }

    /**
     * Deletes a municipality by its ID.
     *
     * # Arguments
     * `municipality_id`: The ID of the municipality to be deleted.
     *
     * # Returns
     * A Result indicating success or an `ApplicationError`.
     */
    #[instrument(skip(self))]
    pub async fn delete_municipality(&self, municipality_id: i64) -> Result<(), ApplicationError> {
        let span: tracing::Span = tracing::Span::current();
        let Some(connection_pool) = &self.connection_pool else { 
            return Err(ApplicationError::new(ErrorType::DatabaseError, "No database connection available".to_string())) 
        };
        let mut transaction = connection_pool.begin().instrument(span.clone()).await.map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to begin transaction: {err}")))?;
        match self.statistics_dao.delete_municipality(&mut transaction, municipality_id).instrument(span.clone()).await {
            Ok(()) => transaction.commit().await.map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to commit transaction: {err}")))?,
            Err(err) => {
                transaction.rollback().await.map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to rollback transaction: {err}")))?;
                return Err(err);
            }
        }
        Ok(())
    }

    /**
     * Retrieves a list of statistics based on the provided pagination input.
     *
     * # Arguments
     * `pagination_input`: `PaginationInput` containing pagination information.
     *
     * # Returns
     * A Result containing `StatisticsListOutputType` or an `ApplicationError`.
     */
    #[instrument(skip(self))]
    pub async fn get_statistics_list(&self, pagination_input: PaginationInput) -> Result<StatisticsListOutputType, ApplicationError> {
        let span: tracing::Span = tracing::Span::current();
        let Some(connection_pool) = &self.connection_pool else {
            return Err(ApplicationError::new(ErrorType::DatabaseError, "No database connection available".to_string()))
        };
        self.statistics_dao.get_statistics_list(connection_pool, pagination_input).instrument(span).await
    }

    /**
     * Adds a new statistic.
     *
     * # Arguments
     * `statistics_add_input`: The input type containing the details of the statistic to be added.
     *
     * # Returns
     * A Result indicating success or an `ApplicationError`.
     */
    #[instrument(skip(self))]
    pub async fn add_statistic(&self, statistics_add_input: StatisticAddInputType) -> Result<(), ApplicationError> {
        let span: tracing::Span = tracing::Span::current();
        let Some(connection_pool) = &self.connection_pool else { 
            return Err(ApplicationError::new(ErrorType::DatabaseError, "No database connection available".to_string())) 
        };
        let mut transaction = connection_pool.begin().instrument(span.clone(), ).await.map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to begin transaction: {err}")))?;
        match self.statistics_dao.add_statistics(&mut transaction, statistics_add_input).instrument(span.clone()).await {
            Ok(()) => transaction.commit().await.map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to commit transaction: {err}")))?,
            Err(err) => {
                transaction.rollback().await.map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to rollback transaction: {err}")))?;
                return Err(err);
            }
        }
        Ok(())
    }

    /**
     * Deletes a statistic by its ID.
     *
     * # Arguments
     * `statistics_id`: The ID of the statistic to be deleted.
     *
     * # Returns
     * A Result indicating success or an `ApplicationError`.
     */
    #[instrument(skip(self))]
    pub async fn delete_statistics(&self, statistics_id: i64) -> Result<(), ApplicationError> {
        let span: tracing::Span = tracing::Span::current();
        let Some(connection_pool) = &self.connection_pool else { 
            return Err(ApplicationError::new(ErrorType::DatabaseError, "No database connection available".to_string())) 
        };
        let mut transaction = connection_pool.begin().instrument(span.clone()).await.map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to begin transaction: {err}")))?;
        match self.statistics_dao.delete_statistics(&mut transaction, statistics_id).instrument(span.clone()).await {
            Ok(()) => transaction.commit().await.map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to commit transaction: {err}")))?,
            Err(err) => {
                transaction.rollback().await.map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to rollback transaction: {err}")))?;
                return Err(err);
            }
        }
        Ok(())
    }

    /**
     * Retrieves a list of values based on the provided pagination input and filter parameters.
     *
     * # Arguments
     * `pagination_input`: `PaginationInput` containing pagination information.
     * `filter_params`: `ValuesListInputType` containing filter parameters.
     *
     * # Returns
     * A Result containing `ValuesListOutputType` or an `ApplicationError`.
     */
    #[instrument(skip(self))]
    pub async fn get_values_list(&self, pagination_input: PaginationInput, filter_params: ValuesListInputType) -> Result<ValuesListOutputType, ApplicationError> {
        let span: tracing::Span = tracing::Span::current(); 
        let Some(connection_pool) = &self.connection_pool else { 
            return Err(ApplicationError::new(ErrorType::DatabaseError, "No database connection available".to_string())) 
        };
        self.statistics_dao.get_values_list(connection_pool, pagination_input, filter_params).instrument(span).await
    }

    /**
     * Deletes a value by its ID.
     *
     * # Arguments
     * `statistics_id`: The ID of the statistic to be deleted.
     *
     * # Returns
     * A Result indicating success or an `ApplicationError`.
     */
    #[instrument(skip(self))]
    pub async fn delete_value(&self, value_id: i64) -> Result<(), ApplicationError> {
        let span: tracing::Span = tracing::Span::current();
        let Some(connection_pool) = &self.connection_pool else { 
            return Err(ApplicationError::new(ErrorType::DatabaseError, "No database connection available".to_string())) 
        };
        let mut transaction = connection_pool.begin().instrument(span.clone()).await.map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to begin transaction: {err}")))?;
        match self.statistics_dao.delete_value(&mut transaction, value_id).instrument(span.clone()).await {
            Ok(()) => transaction.commit().await.map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to commit transaction: {err}")))?,
            Err(err) => {
                transaction.rollback().await.map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to rollback transaction: {err}")))?;
                return Err(err);
            }
        }
        Ok(())
    }

    /**
     * Adds a new value.
     *
     * # Arguments
     * `value_add_input`: The input type containing the details of the value to be added.
     *
     * # Returns
     * A Result indicating success or an `ApplicationError`.
     */
    #[instrument(skip(self))]
    pub async fn add_value(&self, value_add_input: ValuesAddUpdateInputType) -> Result<(), ApplicationError> {
        let span: tracing::Span = tracing::Span::current();
        let Some(connection_pool) = &self.connection_pool else { 
            return Err(ApplicationError::new(ErrorType::DatabaseError, "No database connection available".to_string())) 
        };
        let mut transaction = connection_pool.begin().instrument(span.clone()).await.map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to begin transaction: {err}")))?;
        match self.statistics_dao.add_value(&mut transaction, value_add_input).instrument(span.clone()).await {
            Ok(_value_id) => transaction.commit().await.map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to commit transaction: {err}")))?,
            Err(err) => {
                transaction.rollback().await.map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to rollback transaction: {err}")))?;
                return Err(err);
            }
        }
        Ok(())   
    }

    /**
     * Updates an existing value.
     *
     * # Arguments
     * `value_id`: The ID of the value to be updated.
     * `value_add_update_input`: The input type containing the updated details of the value.
     *
     * # Returns
     * A Result indicating success or an `ApplicationError`.
     */
    #[instrument(skip(self))]
    pub async fn update_value(&self, value_id: i64, value_add_update_input: ValuesAddUpdateInputType) -> Result<(), ApplicationError> {
        let span: tracing::Span = tracing::Span::current();
        let Some(connection_pool) = &self.connection_pool else { 
            return Err(ApplicationError::new(ErrorType::DatabaseError, "No database connection available".to_string())) 
        };
        let mut transaction = connection_pool.begin().instrument(span.clone()).await.map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to begin transaction: {err}")))?;
        match self.statistics_dao.update_value(&mut transaction, value_id, value_add_update_input).instrument(span.clone()).await {
            Ok(()) => transaction.commit().await.map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to commit transaction: {err}")))?,
            Err(err) => {
                transaction.rollback().await.map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to rollback transaction: {err}")))?;
                return Err(err);
            }
        }
        Ok(())
    }
}
