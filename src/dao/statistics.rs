use chrono::{DateTime, Utc};
use rust_decimal::Decimal;
use sqlx::{Pool, Postgres};
use tracing::instrument;

use crate::model::{
    apperror::{ApplicationError, ErrorType},
    models::{PaginationInput, PaginationOutput, ValueDetailType, ValuesListInputType, ValuesListOutputType},
};

/**
 * Database response type for querying the values list.
 */
pub type QueryValuesListDbResp = (i64, i64, i64, Decimal, i64, DateTime<Utc>, DateTime<Utc>, String, String, String, String);

/**
 * SQL query to retrieve a list of values based on municipality ID, statistic ID, and year.
 *
 * The query retrieves the ID, municipality ID, statistic ID, value, year, updated_at, inserted_at,
 * updated_by, inserted_by, municipality name, and statistic name from the data table,
 * joining with the municipality and statistics tables.
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
     * Creates a new instance of StatisticsDao.
     *
     * # Returns
     * A new instance of StatisticsDao.
     */
    pub fn new() -> Self {
        StatisticsDao {}
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
     * A result containing the ValuesListOutputType with the retrieved values and pagination information.
     */
    #[instrument(level = "info", skip(self, connection_pool), fields(result))]
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
        let pagination_output = Self::get_pagination_output(&pagination_input, &elements);
        elements.truncate(pagination_input.page_size as usize);
        Ok(ValuesListOutputType::new(elements, pagination_output))
    }

    /**
     * Constructs a PaginationOutput based on the pagination input and the number of elements.
     *
     * # Arguments
     * `pagination_input`: The input containing pagination parameters.
     * `elements`: The list of elements retrieved from the database.
     *
     * # Returns
     * A PaginationOutput instance containing pagination details.
     */
    fn get_pagination_output(pagination_input: &PaginationInput, elements: &[ValueDetailType]) -> PaginationOutput {
        let has_more_elements = elements.len() > pagination_input.page_size as usize;
        PaginationOutput::new(pagination_input.start_index, pagination_input.page_size, has_more_elements)
    }
}
