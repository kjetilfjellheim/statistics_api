use sqlx::{Pool, Postgres};

use crate::{
    dao::statistics::StatisticsDao,
    model::{
        apperror::{ApplicationError, ErrorType},
        models::{PaginationInput, StatisticAddInputType, StatisticsListOutputType, ValuesListInputType, ValuesListOutputType},
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
    connection_pool: Option<Pool<Postgres>>,
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
    pub fn new(statistics_dao: StatisticsDao, connection_pool: Option<Pool<Postgres>>) -> Self {
        StatisticsService { statistics_dao, connection_pool }
    }

    /**
     * Retrieves a list of statistics based on the provided pagination input.
     *
     * # Arguments
     * `pagination_input`: `PaginationInput` containing pagination information.
     *
     * # Returns
     * A Result containing `ValuesListOutputType` or an `ApplicationError`.
     */
    pub async fn get_statistics_list(&self, pagination_input: PaginationInput) -> Result<StatisticsListOutputType, ApplicationError> {
        let Some(connection_pool) = &self.connection_pool else { 
            return Err(ApplicationError::new(ErrorType::DatabaseError, "No database connection available".to_string())) 
        };
        self.statistics_dao.get_statistics_list(connection_pool, pagination_input).await
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
    pub async fn add_statistic(&self, statistics_add_input: StatisticAddInputType) -> Result<(), ApplicationError> {
        let Some(connection_pool) = &self.connection_pool else { 
            return Err(ApplicationError::new(ErrorType::DatabaseError, "No database connection available".to_string())) 
        };
        let mut transaction = connection_pool.begin().await.map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to begin transaction: {err}")))?;
        match self.statistics_dao.add_statistics(&mut transaction, statistics_add_input).await {
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
    pub async fn delete_statistics(&self, statistics_id: i64) -> Result<(), ApplicationError> {
        let Some(connection_pool) = &self.connection_pool else { 
            return Err(ApplicationError::new(ErrorType::DatabaseError, "No database connection available".to_string())) 
        };
        let mut transaction = connection_pool.begin().await.map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to begin transaction: {err}")))?;
        match self.statistics_dao.delete_statistics(&mut transaction, statistics_id).await {
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
    pub async fn get_values_list(&self, pagination_input: PaginationInput, filter_params: ValuesListInputType) -> Result<ValuesListOutputType, ApplicationError> {
        let Some(connection_pool) = &self.connection_pool else { 
            return Err(ApplicationError::new(ErrorType::DatabaseError, "No database connection available".to_string())) 
        };
        self.statistics_dao.get_values_list(connection_pool, pagination_input, filter_params).await
    }
}
