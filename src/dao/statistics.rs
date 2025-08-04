use std::borrow::Cow;

use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use sqlx::PgConnection;
use tracing::{Instrument, instrument};

use crate::model::{
    apperror::{ApplicationError, ErrorType},
    models::{
        MunicipalityAddInputType, MunicipalityDetailType, MunicipalityListOutputType, PaginationInput, PaginationOutput, StatisticAddInputType, StatisticDetailType, StatisticsListOutputType,
        ValueDetailType, ValuesAddUpdateInputType, ValuesListInputType, ValuesListOutputType,
    },
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
const QUERY_MUNICIPALITY_LIST: &str = "SELECT id, name, inserted_at, inserted_by FROM municipality ORDER BY id LIMIT $1 OFFSET $2";

/**
 * SQL query to add a new statistic.
 */
const ADD_STATISTIC: &str = "INSERT INTO statistics (id, name, inserted_by, inserted_at) VALUES ($1, $2, $3, now())";

/**
 * SQL query to add a new municipality.
 */
const ADD_MUNICIPALITY: &str = "INSERT INTO municipality (id, name, inserted_by, inserted_at) VALUES ($1, $2, $3, now())";

/**
* SQL query next value id.
*/
const NEXT_VALUE_ID: &str = "SELECT nextval('data_id_seq')";

/**
* SQL query to delete a value.
*/
const DELETE_VALUE: &str = "DELETE FROM data WHERE id = $1";
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
    #[instrument(skip(self, connection_pool), fields(result))]
    pub async fn get_municipality_list(&self, connection_pool: &mut PgConnection, pagination_input: PaginationInput) -> Result<MunicipalityListOutputType, ApplicationError> {
        let span = tracing::Span::current();
        let results: Vec<QueryMunicipalityListDbResp> = sqlx::query_as(QUERY_MUNICIPALITY_LIST)
            .bind(pagination_input.page_size + 1)
            .bind(pagination_input.start_index)
            .fetch_all(connection_pool)
            .instrument(span)
            .await
            .map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to execute query to get municipality list: {err}")))?;
        let mut elements: Vec<MunicipalityDetailType> = results.into_iter().map(MunicipalityDetailType::from).collect();
        let pagination_output = Self::get_pagination_output(
            &pagination_input,
            i64::try_from(elements.len()).map_err(|err| ApplicationError::new(ErrorType::Validation, format!("Failed to get pagination output: {err}")))?,
        );
        elements.truncate(usize::try_from(pagination_input.page_size).map_err(|err| ApplicationError::new(ErrorType::Validation, format!("Failed to truncate elements: {err}")))?);
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
    #[instrument(skip(self, transaction), fields(result))]
    pub async fn add_municipality(&self, transaction: &mut PgConnection, municipality_add_input: MunicipalityAddInputType) -> Result<(), ApplicationError> {
        let span = tracing::Span::current();
        sqlx::query(ADD_MUNICIPALITY)
            .bind(municipality_add_input.id)
            .bind(municipality_add_input.name)
            .bind(municipality_add_input.created_by)
            .execute(transaction)
            .instrument(span)
            .await
            .map_err(|err| Self::handle_database_error(err.as_database_error()))?;
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
    #[instrument(skip(self, transaction), fields(result))]
    pub async fn delete_municipality(&self, transaction: &mut PgConnection, municipality_id: i64) -> Result<(), ApplicationError> {
        let span = tracing::Span::current();
        let result = sqlx::query(DELETE_MUNICIPALITY)
            .bind(municipality_id)
            .execute(transaction)
            .instrument(span)
            .await
            .map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to execute query to delete municipality: {err}")))?;
        if result.rows_affected() == 0 {
            tracing::debug!("Municipality with ID {} not found for deletion", municipality_id);
            return Err(ApplicationError::new(ErrorType::NotFound, "Municipality not found".to_string()));
        }
        if result.rows_affected() > 1 {
            tracing::warn!("Multiple municipalities attempted deleted. Rolled back");
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
    #[instrument(skip(self, connection_pool), fields(result))]
    pub async fn get_statistics_list(&self, connection_pool: &mut PgConnection, pagination_input: PaginationInput) -> Result<StatisticsListOutputType, ApplicationError> {
        let span = tracing::Span::current();
        let results: Vec<QueryStatisticListDbResp> = sqlx::query_as(QUERY_STATISTICS_LIST)
            .bind(pagination_input.page_size + 1)
            .bind(pagination_input.start_index)
            .fetch_all(connection_pool)
            .instrument(span.clone())
            .await
            .map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to execute query to get statistics list: {err}")))?;
        let mut elements: Vec<StatisticDetailType> = results.into_iter().map(StatisticDetailType::from).collect();
        let pagination_output = Self::get_pagination_output(
            &pagination_input,
            i64::try_from(elements.len()).map_err(|err| ApplicationError::new(ErrorType::Validation, format!("Failed to get pagination output: {err}")))?,
        );
        elements.truncate(usize::try_from(pagination_input.page_size).map_err(|err| ApplicationError::new(ErrorType::Validation, format!("Failed to truncate elements: {err}")))?);
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
    #[instrument(skip(self, transaction), fields(result))]
    pub async fn add_statistics(&self, transaction: &mut PgConnection, statistics_add_input: StatisticAddInputType) -> Result<(), ApplicationError> {
        let span = tracing::Span::current();
        sqlx::query(ADD_STATISTIC)
            .bind(statistics_add_input.id)
            .bind(statistics_add_input.name)
            .bind(statistics_add_input.created_by)
            .execute(transaction)
            .instrument(span)
            .await
            .map_err(|err| Self::handle_database_error(err.as_database_error()))?;
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
    #[instrument(skip(self, transaction), fields(result))]
    pub async fn delete_statistics(&self, transaction: &mut PgConnection, statistics_id: i64) -> Result<(), ApplicationError> {
        let span = tracing::Span::current();
        let result = sqlx::query(DELETE_STATISTIC)
            .bind(statistics_id)
            .execute(transaction)
            .instrument(span.clone())
            .await
            .map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to execute query to delete statistics: {err}")))?;
        if result.rows_affected() == 0 {
            tracing::debug!("Statistics with ID {} not found for deletion", statistics_id);
            return Err(ApplicationError::new(ErrorType::NotFound, "Statistics not found".to_string()));
        }
        if result.rows_affected() > 1 {
            tracing::warn!("Multiple statistics attempted deleted. Rolled back");
            return Err(ApplicationError::new(ErrorType::Application, "Multiple statistics attempted deleted. Rolled back".to_string()));
        }
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
    #[instrument(skip(self, transaction), fields(result))]
    pub async fn delete_value(&self, transaction: &mut PgConnection, value_id: i64) -> Result<(), ApplicationError> {
        let span = tracing::Span::current();
        let result = sqlx::query(DELETE_VALUE)
            .bind(value_id)
            .execute(transaction)
            .instrument(span.clone())
            .await
            .map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to execute query to delete value: {err}")))?;
        if result.rows_affected() == 0 {
            tracing::debug!("Value with ID {} not found for deletion", value_id);
            return Err(ApplicationError::new(ErrorType::NotFound, "Value not found".to_string()));
        }
        if result.rows_affected() > 1 {
            tracing::warn!("Multiple values attempted deleted. Rolled back");
            return Err(ApplicationError::new(ErrorType::Application, "Multiple values attempted deleted. Rolled back".to_string()));
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
    #[instrument(skip(self, connection_pool), fields(result))]
    pub async fn get_values_list(&self, connection_pool: &mut PgConnection, pagination_input: PaginationInput, filter_params: ValuesListInputType) -> Result<ValuesListOutputType, ApplicationError> {
        let span = tracing::Span::current();
        let results: Vec<QueryValuesListDbResp> = sqlx::query_as(QUERY_VALUES_LIST)
            .bind(filter_params.id_municipality)
            .bind(filter_params.id_statistic)
            .bind(filter_params.year)
            .bind(pagination_input.page_size + 1)
            .bind(pagination_input.start_index)
            .fetch_all(connection_pool)
            .instrument(span.clone())
            .await
            .map_err(|err| ApplicationError::new(ErrorType::DatabaseError, format!("Failed to execute query for values list: {err}")))?;
        let mut elements: Vec<ValueDetailType> = results.into_iter().map(ValueDetailType::from).collect();
        let pagination_output = Self::get_pagination_output(
            &pagination_input,
            i64::try_from(elements.len()).map_err(|err| ApplicationError::new(ErrorType::Validation, format!("Failed to get pagination output: {err}")))?,
        );
        elements.truncate(usize::try_from(pagination_input.page_size).map_err(|err| ApplicationError::new(ErrorType::Validation, format!("Failed to truncate elements: {err}")))?);
        Ok(ValuesListOutputType::new(elements, pagination_output))
    }

    /**
     * Adds a new value to the database.
     *
     * # Arguments
     * `transaction`: The database transaction to execute the query within.
     * `value_add_input`: The input containing details of the value to be added.
     *
     * # Returns
     * A result indicating success or failure of the operation.
     */
    #[instrument(skip(self, transaction), fields(result))]
    pub async fn add_value(&self, transaction: &mut PgConnection, value_add_input: ValuesAddUpdateInputType) -> Result<i64, ApplicationError> {
        let span = tracing::Span::current();
        let next_id: (i64,) = sqlx::query_as(NEXT_VALUE_ID).fetch_one(transaction.as_mut()).instrument(span.clone()).await.map_err(|err| Self::handle_database_error(err.as_database_error()))?;

        sqlx::query("INSERT INTO data (id, id_municipality, id_statistic, value, year, inserted_by, updated_by, inserted_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $6, now(), now())")
            .bind(next_id.0)
            .bind(value_add_input.id_municipality)
            .bind(value_add_input.id_statistic)
            .bind(value_add_input.value)
            .bind(value_add_input.year)
            .bind(value_add_input.claim_name)
            .execute(transaction)
            .instrument(span.clone())
            .await
            .map_err(|err| Self::handle_database_error(err.as_database_error()))?;
        Ok(next_id.0)
    }

    /**
     * Updates an existing value in the database.
     *
     * # Arguments
     * `transaction`: The database transaction to execute the query within.
     * `value_id`: The ID of the value to be updated.
     * `value_add_update_input`: The input containing updated details of the value.
     *
     * # Returns
     * A result indicating success or failure of the operation.
     */
    #[instrument(skip(self, transaction), fields(result))]
    pub async fn update_value(&self, transaction: &mut PgConnection, value_id: i64, value_add_update_input: ValuesAddUpdateInputType) -> Result<(), ApplicationError> {
        let span = tracing::Span::current();
        let result = sqlx::query("UPDATE data SET id_municipality = $1, id_statistic = $2, value = $3, year = $4, updated_by = $5, updated_at = now() WHERE id = $6")
            .bind(value_add_update_input.id_municipality)
            .bind(value_add_update_input.id_statistic)
            .bind(value_add_update_input.value)
            .bind(value_add_update_input.year)
            .bind(value_add_update_input.claim_name)
            .bind(value_id)
            .execute(transaction)
            .instrument(span.clone())
            .await
            .map_err(|err| Self::handle_database_error(err.as_database_error()))?;
        if result.rows_affected() == 0 {
            tracing::debug!("Value with id {} not found for update", value_id);
            return Err(ApplicationError::new(ErrorType::NotFound, "Value not found".to_string()));
        }
        if result.rows_affected() > 1 {
            tracing::warn!("Multiple values attempted updated. Rolled back");
            return Err(ApplicationError::new(ErrorType::Application, "Multiple values attempted updated. Rolled back".to_string()));
        }
        Ok(())
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
            tracing::debug!("Database error: {}", db_error);
            tracing::info!("Add/Update error: {:?}", db_error.code());
            if db_error.code() == Some(Cow::Borrowed("23505")) {
                // Unique violation
                return ApplicationError::new(ErrorType::ConstraintViolation, "Already exists".to_string());
            } else if db_error.code() == Some(Cow::Borrowed("23503")) {
                // Foreign key violation
                return ApplicationError::new(ErrorType::ConstraintViolation, "Missing parent value".to_string());
            } else if db_error.code() == Some(Cow::Borrowed("22001")) {
                // Value too long
                return ApplicationError::new(ErrorType::Validation, "Value too long".to_string());
            }
            tracing::error!("Unhandled database error: {}", db_error);
            return ApplicationError::new(ErrorType::DatabaseError, "Unhandled database error".to_string());
        }
        ApplicationError::new(ErrorType::DatabaseError, "Failed to execute database operation".to_string())
    }
}

#[cfg(test)]
mod test {
    use crate::{dao::statistics::StatisticsDao, model::models::PaginationInput};

    #[test]
    fn test_pagination_output_has_more() {
        let pagination_input = PaginationInput { start_index: 0, page_size: 10 };
        let elements_size = 11;
        let pagination_output = StatisticsDao::get_pagination_output(&pagination_input, elements_size);
        assert_eq!(pagination_output.start_index, 0);
        assert_eq!(pagination_output.page_size, 10);
        assert!(pagination_output.has_more);
    }

    #[test]
    fn test_pagination_output_has_no_more() {
        let pagination_input = PaginationInput { start_index: 0, page_size: 10 };
        let elements_size = 10;
        let pagination_output = StatisticsDao::get_pagination_output(&pagination_input, elements_size);
        assert_eq!(pagination_output.start_index, 0);
        assert_eq!(pagination_output.page_size, 10);
        assert!(!pagination_output.has_more);
    }
}

#[cfg(feature = "integration-test")]
#[cfg(test)]
mod integration_test {
    use super::*;
    use sqlx::PgPool;

    #[sqlx::test]
    async fn test_get_municipality_list() {
        let pool = init_db().await;
        let statistics_dao = StatisticsDao::new();
        let pagination_input = PaginationInput { start_index: 0, page_size: 10 };
        let mut connection = pool.acquire().await.unwrap();
        let result = statistics_dao.get_municipality_list(&mut connection, pagination_input).await;
        assert!(result.is_ok());
    }

    #[sqlx::test]
    async fn test_add_then_delete_municipality() {
        let pool = init_db().await;
        let mut transaction = pool.begin().await.unwrap();
        let statistics_dao = StatisticsDao::new();
        let municipality_add_input = MunicipalityAddInputType { id: 1, name: "Test Municipality".to_string(), created_by: "test_user".to_string() };
        let add_result = statistics_dao.add_municipality(&mut transaction, municipality_add_input).await;
        assert!(add_result.is_ok());
        let delete_result = statistics_dao.delete_municipality(&mut transaction, 1).await;
        assert!(delete_result.is_ok());
        transaction.rollback().await.unwrap(); // Rollback the transaction to avoid leaving test data in the database
    }

    #[sqlx::test]
    async fn test_get_statistics_list() {
        let pool = init_db().await;
        let statistics_dao = StatisticsDao::new();
        let pagination_input = PaginationInput { start_index: 0, page_size: 10 };
        let mut connection = pool.acquire().await.unwrap();
        let result = statistics_dao.get_statistics_list(&mut connection, pagination_input).await;
        assert!(result.is_ok());
    }

    #[sqlx::test]
    async fn test_add_then_delete_statistics() {
        let pool = init_db().await;
        let mut transaction = pool.begin().await.unwrap();
        let statistics_dao = StatisticsDao::new();
        let statistics_add_input = StatisticAddInputType { id: 1, name: "Test Statistics".to_string(), created_by: "test_user".to_string() };
        let add_result = statistics_dao.add_statistics(&mut transaction, statistics_add_input).await;
        assert!(add_result.is_ok());
        let delete_result = statistics_dao.delete_statistics(&mut transaction, 1).await;
        assert!(delete_result.is_ok());
        transaction.rollback().await.unwrap(); // Rollback the transaction to avoid leaving test data in the database
    }

    #[sqlx::test]
    async fn test_list_values() {
        let pool = init_db().await;
        let mut transaction = pool.begin().await.unwrap();
        let statistics_dao = StatisticsDao::new();
        let statistics_add_input = StatisticAddInputType { id: 1, name: "Test Statistics".to_string(), created_by: "test_user".to_string() };
        let add_result = statistics_dao.add_statistics(&mut transaction, statistics_add_input).await;
        assert!(add_result.is_ok());
        let municipality_add_input = MunicipalityAddInputType { id: 1, name: "Test Municipality".to_string(), created_by: "test_user".to_string() };
        let add_result = statistics_dao.add_municipality(&mut transaction, municipality_add_input).await;
        assert!(add_result.is_ok());
        let values_list_input = ValuesListInputType { id_municipality: Some(1), id_statistic: Some(1), year: Some(2023) };
        let mut connection = pool.acquire().await.unwrap();
        let values_list_output = statistics_dao.get_values_list(&mut connection, PaginationInput { start_index: 0, page_size: 10 }, values_list_input).await;
        assert!(values_list_output.is_ok());
    }

    #[sqlx::test]
    async fn test_add_update_then_delete_value() {
        let pool = init_db().await;
        let mut transaction = pool.begin().await.unwrap();
        let statistics_dao = StatisticsDao::new();
        let statistics_add_input = StatisticAddInputType { id: 1, name: "Test Statistics".to_string(), created_by: "test_user".to_string() };
        let add_result = statistics_dao.add_statistics(&mut transaction, statistics_add_input).await;
        assert!(add_result.is_ok());
        let municipality_add_input = MunicipalityAddInputType { id: 1, name: "Test Municipality".to_string(), created_by: "test_user".to_string() };
        let add_result = statistics_dao.add_municipality(&mut transaction, municipality_add_input).await;
        assert!(add_result.is_ok());
        let value_add_input = ValuesAddUpdateInputType { id_municipality: 1, id_statistic: 1, value: Decimal::new(100, 2), year: 2023, claim_name: "test_user".to_string() };
        let add_result = statistics_dao.add_value(&mut transaction, value_add_input.clone()).await;
        assert!(add_result.is_ok());

        let update_result = statistics_dao.update_value(&mut transaction, add_result.clone().unwrap(), value_add_input).await;
        assert!(update_result.is_ok());

        let delete_result = statistics_dao.delete_value(&mut transaction, add_result.unwrap()).await;
        assert!(delete_result.is_ok());
        transaction.rollback().await.unwrap(); // Rollback the transaction to avoid leaving test data in the database
    }

    /**
     * Initialize the database connection pool.
     */
    async fn init_db() -> PgPool {
        dotenv::from_filename("./sqlx-postgresql-migration/.env-test").ok();
        let pool = PgPool::connect(dotenv::var("DATABASE_URL").unwrap().as_str()).await.unwrap();
        sqlx::migrate!("./sqlx-postgresql-migration/migrations").run(&pool).await.unwrap();
        pool
    }
}
