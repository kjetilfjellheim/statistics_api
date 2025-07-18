use sqlx::{Pool, Postgres};

use crate::{
    dao::statistics::StatisticsDao,
    model::{
        apperror::{ApplicationError, ErrorType},
        models::{PaginationInput, ValuesListInputType, ValuesListOutputType},
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
     * Creates a new instance of StatisticsService.
     *
     * # Arguments
     * `statistics_dao`: The DAO for statistics operations.
     * `connection_pool`: Optional connection pool for database operations.
     *
     * # Returns
     * A new instance of StatisticsService.
     */
    pub fn new(statistics_dao: StatisticsDao, connection_pool: Option<Pool<Postgres>>) -> Self {
        StatisticsService { statistics_dao, connection_pool }
    }

    /**
     * Retrieves a list of values based on the provided pagination input and filter parameters.
     *
     * # Arguments
     * `pagination_input`: PaginationInput containing pagination information.
     * `filter_params`: ValuesListInputType containing filter parameters.
     *
     * # Returns
     * A Result containing ValuesListOutputType or an ApplicationError.
     */
    pub async fn get_values_list(&self, pagination_input: PaginationInput, filter_params: ValuesListInputType) -> Result<ValuesListOutputType, ApplicationError> {
        let connection_pool = match &self.connection_pool {
            Some(pool) => pool,
            None => return Err(ApplicationError::new(ErrorType::DatabaseError, "No database connection available".to_string())),
        };
        self.statistics_dao.get_values_list(connection_pool, pagination_input, filter_params).await
    }
}
