use std::borrow::Cow;

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use sqlx::{PgConnection, Pool, Postgres};
use tracing::instrument;

use crate::model::{
    apperror::{ApplicationError, ErrorType},
    models::{MunicipalityAddInputType, MunicipalityDetailType, MunicipalityListOutputType, PaginationInput, PaginationOutput, StatisticAddInputType, StatisticDetailType, StatisticsListOutputType, ValueDetailType, ValuesListInputType, ValuesListOutputType},
};

/**
 * Database response type for querying the values list.
 */
pub type QueryValuesListDbResp = (i64, i64, i64, Decimal, i64, DateTime<Utc>, DateTime<Utc>, String, String, String, String);

/**
 * Database response type for querying the statistics list.
 */
pub type QueryStatisticListDbResp = (i64, String, DateTime<Utc>, String);

/**
 * Database response type for querying the municipality list.
 */
pub type QueryMunicipalityListDbResp = (i64, String, DateTime<Utc>, String);

/**
 * SQL query to retrieve a list of statistics.
 */
const QUERY_STATISTICS_LIST: &str = "SELECT id, name, inserted_at, inserted_by FROM statistics ORDER BY id LIMIT $1 OFFSET $2";

/**
 * SQL query to retrieve a list of municipalities.
 */
const QUERY_MUNICIPALITY_LIST: &str = "SELECT id, name, created_at, created_by FROM municipality ORDER BY id LIMIT $1 OFFSET $2";

/**
 * SQL query to add a new statistic.
 */
const ADD_STATISTIC: &str = "INSERT INTO statistics (id, name, inserted_by, inserted_at) VALUES ($1, $2, $3, now())";

/**
 * SQL query to add a new municipality.
 */
const ADD_MUNICIPALITY: &str = "INSERT INTO municipality (id, name, created_by, created_at) VALUES ($1, $2, $3, now())";


/**
* SQL query to delete a statistic.
*/
const DELETE_STATISTIC: &str = "DELETE FROM statistics WHERE id = $1";

/**
 * SQL query to delete a municipality.
 */
const DELETE_MUNICIPALITY: &str = "DELETE FROM municipality WHERE id = $1";

/**
 * SQL query to retrieve a list of values based on municipality ID, statistic ID, and year.
 */
const QUERY_VALUES_LIST: &str =
    "SELECT a.id, a.id_municipality, a.id_statistic, a.value, a.year, a.updated_at, a.inserted_at, a.updated_by, a.inserted_by, b.name AS municipality_name, c.name AS statistic_name 
                                 FROM data a, municipality b, statistics c 
                                 WHERE a.id_municipality = b.id AND a.id_statistic = c.id AND 
                                 ($1::bigint IS NULL OR a.id_municipality = $1) AND 
                                 ($2::bigint IS NULL OR a.id_statistic = $2) AND 
                                 ($3::bigint IS NULL OR a.year = $3)
                                 ORDER BY id_municipality, id_statistic, year
                                 LIMIT $4 OFFSET $5";

/**
 * DAO for statistics-related database operations.
 */
pub struct StatisticsDao {}

impl StatisticsDao {
    /**
     * Creates a new instance of `StatisticsDao`.
     *
     * # Returns
     * A new instance of `StatisticsDao`.
     */
    pub fn new() -> Self {
        StatisticsDao {}
    }

    /**
     * Retrieves a list of municipalities based on the provided pagination input.
     *
     * # Arguments
     * `connection_pool`: The database connection pool.
     * `pagination_input`: `PaginationInput` containing pagination information.
     *
     * # Returns
     * A Result containing `MunicipalityListOutputType` or an `ApplicationError`.
     */
    #[instrument(level = "debug", skip(self, connection_pool), fields(result))]
    pub async fn get_municipality_list(&self, connection_pool: &Pool<Postgres>, pagination_input: PaginationInput) -> Result<MunicipalityListOutputType, ApplicationError> {
        let results: Vec<QueryMunicipalityListDbResp> = sqlx::query_as(QUERY_MUNICIPALITY_LIST)
            .bind(pagination_input.page_size + 1)
            .bind(pagination_input.start_index)
            .fetch_all(connection_pool)
            .await
            .map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to execute query to get municipality list: {err}")))?;
        let mut elements: Vec<MunicipalityDetailType> = results.into_iter().map(MunicipalityDetailType::from).collect();
        let pagination_output = Self::get_pagination_output(&pagination_input, i64::try_from(elements.len()).map_err(|_| ApplicationError::new(ErrorType::InvalidInput, "Invalid elements length".to_string()))?);
        elements.truncate(usize::try_from(pagination_input.page_size).map_err(|_| ApplicationError::new(ErrorType::InvalidInput, "Invalid page size".to_string()))?);
        Ok(MunicipalityListOutputType::new(elements, pagination_output))
    }

    /**
     * Adds a new municipality to the database.
     *
     * # Arguments
     * `connection_pool`: The database connection pool.
     * `municipality_add_input`: The input containing details of the municipality to be added.
     *
     * # Returns
     * A result indicating success or failure of the operation.
     */
    #[instrument(level = "debug", skip(self, transaction), fields(result))]
    pub async fn add_municipality(&self, transaction: &mut PgConnection, municipality_add_input: MunicipalityAddInputType) -> Result<(), ApplicationError> {
        sqlx::query(ADD_MUNICIPALITY)
            .bind(municipality_add_input.id)
            .bind(municipality_add_input.name)
            .bind(municipality_add_input.created_by)
            .execute(transaction)
            .await
            .map_err(|err| {
                Self::handle_database_error(err.as_database_error())
            })?;
        Ok(())
    }

    /**
     * Deletes a municipality from the database by its ID.
     *
     * # Arguments
     * `connection_pool`: The database connection pool.
     * `municipality_id`: The ID of the municipality to be deleted.
     *
     * # Returns
     * A result indicating success or failure of the operation.
     */
    #[instrument(level = "debug", skip(self, transaction), fields(result))]
    pub async fn delete_municipality(&self, transaction: &mut PgConnection, municipality_id: i64) -> Result<(), ApplicationError> {
        let result =sqlx::query(DELETE_MUNICIPALITY)
            .bind(municipality_id)
            .execute(transaction)
            .await
            .map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to execute query to delete municipality: {err}")))?;
        if result.rows_affected() == 0 {
            return Err(ApplicationError::new(ErrorType::NotFound, "Municipality not found".to_string()));
        }
        if result.rows_affected() > 1 {
            return Err(ApplicationError::new(ErrorType::Application, "Multiple municipalities attempted deleted. Rolled back".to_string()));
        }
        Ok(())
    }

    /**
     * Retrieves a list of statistics based on the provided pagination input.
     *
     * # Arguments
     * `connection_pool`: The database connection pool.
     * `pagination_input`: `PaginationInput` containing pagination information.
     *
     * # Returns
     * A Result containing `StatisticsListOutputType` or an `ApplicationError`.
     */
    #[instrument(level = "debug", skip(self, connection_pool), fields(result))]
    pub async fn get_statistics_list(&self, connection_pool: &Pool<Postgres>, pagination_input: PaginationInput) -> Result<StatisticsListOutputType, ApplicationError> {
        let results: Vec<QueryStatisticListDbResp> = sqlx::query_as(QUERY_STATISTICS_LIST)
            .bind(pagination_input.page_size + 1)
            .bind(pagination_input.start_index)
            .fetch_all(connection_pool)
            .await
            .map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to execute query to get statistics list: {err}")))?;
        let mut elements: Vec<StatisticDetailType> = results.into_iter().map(StatisticDetailType::from).collect();
        let pagination_output = Self::get_pagination_output(&pagination_input, i64::try_from(elements.len()).map_err(|_| ApplicationError::new(ErrorType::InvalidInput, "Invalid elements length".to_string()))?);
        elements.truncate(usize::try_from(pagination_input.page_size).map_err(|_| ApplicationError::new(ErrorType::InvalidInput, "Invalid page size".to_string()))?);
        Ok(StatisticsListOutputType::new(elements, pagination_output))
    }

    /**
     * Adds a new statistic to the database.
     *
     * # Arguments
     * `connection_pool`: The database connection pool.
     * `statistics_add_input`: The input containing details of the statistic to be added.
     *
     * # Returns
     * A result indicating success or failure of the operation.
     */
    #[instrument(level = "debug", skip(self, transaction), fields(result))]
    pub async fn add_statistics(&self, transaction: &mut PgConnection, statistics_add_input: StatisticAddInputType) -> Result<(), ApplicationError> {
        sqlx::query(ADD_STATISTIC)
            .bind(statistics_add_input.id)
            .bind(statistics_add_input.name)
            .bind(statistics_add_input.created_by)
            .execute(transaction)
            .await
            .map_err(|err| {
                Self::handle_database_error(err.as_database_error())
            })?;
        Ok(())
    }

    /**
     * Deletes a statistic from the database by its ID.
     *
     * # Arguments
     * `connection_pool`: The database connection pool.
     * `statistics_id`: The ID of the statistic to be deleted.
     *
     * # Returns
     * A result indicating success or failure of the operation.
     */
    #[instrument(level = "debug", skip(self, transaction), fields(result))]
    pub async fn delete_statistics(&self, transaction: &mut PgConnection, statistics_id: i64) -> Result<(), ApplicationError> {
        let result =sqlx::query(DELETE_STATISTIC)
            .bind(statistics_id)
            .execute(transaction)
            .await
            .map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to execute query to delete statistics: {err}")))?;
        if result.rows_affected() == 0 {
            return Err(ApplicationError::new(ErrorType::NotFound, "Statistics not found".to_string()));
        }
        if result.rows_affected() > 1 {
            return Err(ApplicationError::new(ErrorType::Application, "Multiple statistics attempted deleted. Rolled back".to_string()));
        }
        Ok(())
    }

    /**
     * Retrieves a list of values based on the provided pagination input and filter parameters.
     *
     * # Arguments
     * `connection_pool`: The database connection pool.
     * `pagination_input`: The pagination input containing start index and page size.
     * `filter_params`: The filter parameters for municipality ID, statistic ID, and year.
     *
     * # Returns
     * A result containing the `ValuesListOutputType` with the retrieved values and pagination information.
     */
    #[instrument(level = "debug", skip(self, connection_pool), fields(result))]
    pub async fn get_values_list(&self, connection_pool: &Pool<Postgres>, pagination_input: PaginationInput, filter_params: ValuesListInputType) -> Result<ValuesListOutputType, ApplicationError> {
        let results: Vec<QueryValuesListDbResp> = sqlx::query_as(QUERY_VALUES_LIST)
            .bind(filter_params.id_municipality)
            .bind(filter_params.id_statistic)
            .bind(filter_params.year)
            .bind(pagination_input.page_size + 1)
            .bind(pagination_input.start_index)
            .fetch_all(connection_pool)
            .await
            .map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to execute query for values list: {err}")))?;
        let mut elements: Vec<ValueDetailType> = results.into_iter().map(ValueDetailType::from).collect();
        let pagination_output = Self::get_pagination_output(&pagination_input, i64::try_from(elements.len()).map_err(|_| ApplicationError::new(ErrorType::InvalidInput, "Invalid elements length".to_string()))?);
        elements.truncate(usize::try_from(pagination_input.page_size).map_err(|_| ApplicationError::new(ErrorType::InvalidInput, "Invalid page size".to_string()))?);
        Ok(ValuesListOutputType::new(elements, pagination_output))
    }

    /**
     * Constructs a `PaginationOutput` based on the pagination input and the number of elements.
     *
     * # Arguments
     * `pagination_input`: The input containing pagination parameters.
     * `elements_size`: The number of elements retrieved from the database.
     *
     * # Returns
     * A `PaginationOutput` instance containing pagination details.
     */
    fn get_pagination_output(pagination_input: &PaginationInput, elements_size: i64) -> PaginationOutput {
        let has_more_elements = elements_size > pagination_input.page_size;
        PaginationOutput::new(pagination_input.start_index, pagination_input.page_size, has_more_elements)
    }

    /**
     * Handles database errors and maps them to application errors.
     *
     * # Arguments
     * `error`: The database error to handle.
     *
     * # Returns
     * An `ApplicationError` corresponding to the database error.
     */
    fn handle_database_error(error: Option<&dyn sqlx::error::DatabaseError>) -> ApplicationError {
        if let Some(db_error) = error {
            if db_error.code() == Some(Cow::Borrowed("23505")) { // Unique violation
                return ApplicationError::new(ErrorType::ConstraintViolation, "Already exists".to_string());
            } else if db_error.code() == Some(Cow::Borrowed("23503")) { // Foreign key violation
                return ApplicationError::new(ErrorType::ConstraintViolation, "Missing parent value".to_string());
            } else if db_error.code() == Some(Cow::Borrowed("22001")) { // Value too long
                return ApplicationError::new(ErrorType::InvalidInput, "Value too long".to_string());                
            }
        }
        ApplicationError::new(ErrorType::DatabaseError, "Failed to execute database operation".to_string())
    }
}

#[cfg(test)]
mod test {
    use crate::{dao::statistics::StatisticsDao, model::models::PaginationInput};

    #[test]
    fn test_pagination_output_has_more() {
        let pagination_input = PaginationInput {
            start_index: 0,
            page_size: 10,
        };
        let elements_size = 11;
        let pagination_output = StatisticsDao::get_pagination_output(&pagination_input, elements_size);
        assert_eq!(pagination_output.start_index, 0);
        assert_eq!(pagination_output.page_size, 10);
        assert!(pagination_output.has_more);
    }

    #[test]
    fn test_pagination_output_has_no_more() {
        let pagination_input = PaginationInput {
            start_index: 0,
            page_size: 10,
        };
        let elements_size = 10;
        let pagination_output = StatisticsDao::get_pagination_output(&pagination_input, elements_size);
        assert_eq!(pagination_output.start_index, 0);
        assert_eq!(pagination_output.page_size, 10);
        assert!(!pagination_output.has_more);
    }


}