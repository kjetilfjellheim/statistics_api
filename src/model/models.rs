use actix_web::web::{self, Query};
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;

use crate::{
    api::rest::{PaginationQuery, StatisticsAddRequest, ValuesListRequest},
    dao::statistics::{QueryStatisticListDbResp, QueryValuesListDbResp},
};

/***************** Statistic:list models *********************/
/**
 * Represents the output type for the Values List API.
 */
#[derive(Debug)]
pub struct StatisticsListOutputType {
    /**
     * A list of value details.
     */
    pub statistics: Vec<StatisticDetailType>,
    /**
     * Pagination information for the values list.
     */
    pub pagination: PaginationOutput,
}

impl StatisticsListOutputType {
    /**
     * Creates a new `StatisticsListOutputType`.
     *
     * # Arguments
     * `statistics`: A vector of `StatisticDetailType` representing the statistics.
     * `pagination`: `PaginationOutput` containing pagination information.
     */
    pub fn new(statistics: Vec<StatisticDetailType>, pagination: PaginationOutput) -> Self {
        StatisticsListOutputType { statistics, pagination }
    }
}

#[derive(Debug)]
pub struct StatisticDetailType {
    /**
     * The unique identifier for the statistic.
     */
    pub id: i64,
    /**
     * The name of the statistic.
     */
    pub name: String,
    /**
     * The timestamp when the statistic was created.
     */
    pub created_at: DateTime<Utc>,
    /**
     * The user who created the statistic.
     */
    pub created_by: String,
}

impl StatisticDetailType {
    /**
     * Creates a new `StatisticDetailType`.
     *
     * # Arguments
     * `id`: The unique identifier for the statistic.
     * `name`: The name of the statistic.
     * `created_at`: The timestamp when the statistic was created.
     * `created_by`: The user who created the statistic.
     *
     * # Returns
     * A new instance of `StatisticDetailType`.
     */
    pub fn new(id: i64, name: String, created_at: DateTime<Utc>, created_by: String) -> Self {
        StatisticDetailType { id, name, created_at, created_by }
    }
}

/**
 * Converts from db query.
 */
impl From<QueryStatisticListDbResp> for StatisticDetailType {
    fn from(value: QueryStatisticListDbResp) -> Self {
        StatisticDetailType::new(value.0, value.1, value.2, value.3)
    }
}

/***************** Statistic:add models *********************/
#[derive(Debug)]
pub struct StatisticAddInputType {
    /**
     * Statistic id.
     */
    pub id: i64,
    /**
     * Name of the statistic.
     */
    pub name: String,
    /**
     * The user who creates the statistic.
     */
    pub created_by: String,
}

impl StatisticAddInputType {
    /**
     * Creates a new `StatisticAddInputType`.
     *
     * # Arguments
     * `id`: The unique identifier for the statistic.
     * `name`: The name of the statistic.
     * `created_by`: The user who creates the statistic.
     *
     * # Returns
     * A new instance of `StatisticAddInputType`.
     */
    pub fn new(id: i64, name: String, created_by: String) -> Self {
        StatisticAddInputType { id, name, created_by }
    }
}

/**
 * Converts from request data and jwt claim name to `StatisticAddInputType`.
 */
impl From<(web::Json<StatisticsAddRequest>, String)> for StatisticAddInputType {
    fn from(from: (web::Json<StatisticsAddRequest>, String)) -> Self {
        StatisticAddInputType::new(from.0.id, from.0.name.clone(), from.1.clone())
    }
}

/***************** Values:list models *********************/

/**
 * Represents the input type for the Values List API.
 */
#[derive(Debug)]
pub struct ValuesListInputType {
    /**
     * Optional municipality ID to filter the values.
     */
    pub id_municipality: Option<i64>,
    /**
     * Optional statistic ID to filter the values.
     */
    pub id_statistic: Option<i64>,
    /**
     * Optional year to filter the values.
     */
    pub year: Option<i64>,
}

/**
 * Converts from `web::Json<ValuesListRequest>` to `ValuesListInputType`.
 */
impl From<web::Json<ValuesListRequest>> for ValuesListInputType {
    fn from(request: web::Json<ValuesListRequest>) -> Self {
        ValuesListInputType { id_municipality: request.municipality_id, id_statistic: request.statistic_id, year: request.year }
    }
}

/**
 * Represents the output type for the Values List API.
 */
#[derive(Debug)]
pub struct ValuesListOutputType {
    /**
     * A list of value details.
     */
    pub statistics: Vec<ValueDetailType>,
    /**
     * Pagination information for the values list.
     */
    pub pagination: PaginationOutput,
}

/**
 * Creates a new `ValuesListOutputType`.
 *
 * # Arguments
 * `statistics`: A vector of `ValueDetailType` representing the values.
 * `pagination`: `PaginationOutput` containing pagination information.
 */
impl ValuesListOutputType {
    pub fn new(statistics: Vec<ValueDetailType>, pagination: PaginationOutput) -> Self {
        ValuesListOutputType { statistics, pagination }
    }
}

/**
 * Represents the details of a value in the Values List API.
 */
#[derive(Debug)]
pub struct ValueDetailType {
    pub id: i64,
    pub municipality_id: i64,
    pub municipality_name: String,
    pub statistic_id: i64,
    pub statistic_name: String,
    pub value: Decimal,
    pub year: i64,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_by: String,
    pub created_by: String,
}

impl ValueDetailType {
    /**
     * Creates a new `ValueDetailType`.
     *
     * # Arguments
     * `id`: The unique identifier for the value.
     * `municipality_id`: The ID of the municipality.
     * `municipality_name`: The name of the municipality.
     * `statistic_id`: The ID of the statistic.
     * `statistic_name`: The name of the statistic.
     * `value`: The value associated with the statistic.
     * `year`: The year of the statistic.
     * `updated_at`: The timestamp when the value was last updated.
     * `created_at`: The timestamp when the value was created.
     * `updated_by`: The user who last updated the value.
     * `created_by`: The user who created the value.
     *
     * # Returns
     * A new instance of `ValueDetailType`.
     */
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: i64,
        municipality_id: i64,
        municipality_name: String,
        statistic_id: i64,
        statistic_name: String,
        value: Decimal,
        year: i64,
        updated_at: DateTime<Utc>,
        created_at: DateTime<Utc>,
        updated_by: String,
        created_by: String,
    ) -> Self {
        ValueDetailType { id, municipality_id, municipality_name, statistic_id, statistic_name, value, year, updated_at, created_at, updated_by, created_by }
    }
}

/**
 * Converts from db query.
 */
impl From<QueryValuesListDbResp> for ValueDetailType {
    fn from(value: QueryValuesListDbResp) -> Self {
        ValueDetailType::new(value.0, value.1, value.9, value.2, value.10, value.3, value.4, value.5, value.6, value.7, value.8)
    }
}

/***************** Common models *********************/

/**
 * Input structure for pagination.
 */
#[derive(Debug)]
pub struct PaginationInput {
    /**
     * The starting index for pagination.
     */
    pub start_index: i64,
    /**
     * The number of items per page.
     */
    pub page_size: i64,
}

impl PaginationInput {
    /**
     * Creates a new `PaginationInput`.
     *
     * # Arguments
     * `start_index`: The starting index for pagination.
     * `page_size`: The number of items per page.
     */
    pub fn new(start_index: i64, page_size: i64) -> Self {
        PaginationInput { start_index, page_size }
    }
}

/**
 * Converts from request query parameters to `PaginationInput`.
 */
impl From<Query<PaginationQuery>> for PaginationInput {
    fn from(query: Query<PaginationQuery>) -> Self {
        PaginationInput::new(query.start_index.unwrap_or(0), query.page_size.unwrap_or(100))
    }
}

/**
 * Output structure for pagination.
 */
#[derive(Debug)]
pub struct PaginationOutput {
    /**
     * The starting index for pagination.
     */
    pub start_index: i64,
    /**
     * The number of items per page.
     */
    pub page_size: i64,
    /**
     * Indicates if there are more items available.
     */
    pub has_more: bool,
}

impl PaginationOutput {
    /**
    * Creates a new `PaginationOutput`.
    *
    * # Arguments
    * `start_index`: The starting index for pagination.
    * `page_size`: The number of items per page.
    * `has_more`: Indicates if there are more items available.
    */
    pub fn new(start_index: i64, page_size: i64, has_more: bool) -> Self {
        PaginationOutput { start_index, page_size, has_more }
    }
}
