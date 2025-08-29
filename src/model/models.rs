use actix_web::web::{self, Query};
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;

use crate::{
    api::rest::{MunicipalityAddRequest, PaginationQuery, StatisticsAddRequest, ValuesAddUpdateRequest, ValuesListRequest},
    dao::statistics::{QueryMunicipalityListDbResp, QueryStatisticListDbResp, QueryValuesListDbResp},
    model::apperror::{ApplicationError, ErrorType},
};

const MAX_PAGE_SIZE: i64 = 100;

/***************** Municipalities:list models *********************/
/**
 * Represents the output type for the Values List API.
 */
#[derive(Debug)]
pub struct MunicipalityListOutputType {
    /**
     * A list of value details.
     */
    pub municipalities: Vec<MunicipalityDetailType>,
    /**
     * Pagination information for the values list.
     */
    pub pagination: PaginationOutput,
}

impl MunicipalityListOutputType {
    /**
     * Creates a new `MunicipalityListOutputType`.
     *
     * # Arguments
     * `statistics`: A vector of `StatisticDetailType` representing the statistics.
     * `pagination`: `PaginationOutput` containing pagination information.
     */
    pub fn new(municipalities: Vec<MunicipalityDetailType>, pagination: PaginationOutput) -> Self {
        MunicipalityListOutputType { municipalities, pagination }
    }
}

#[derive(Debug)]
pub struct MunicipalityDetailType {
    /**
     * The unique identifier for the municipality.
     */
    pub id: i64,
    /**
     * The name of the municipality.
     */
    pub name: String,
    /**
     * The timestamp when the municipality was created.
     */
    pub created_at: DateTime<Utc>,
    /**
     * The user who created the municipality.
     */
    pub created_by: String,
}

impl MunicipalityDetailType {
    /**
     * Creates a new `MunicipalityDetailType`.
     *
     * # Arguments
     * `id`: The unique identifier for the municipality.
     * `name`: The name of the municipality.
     * `created_at`: The timestamp when the municipality was created.
     * `created_by`: The user who created the municipality.
     *
     * # Returns
     * A new instance of `MunicipalityDetailType`.
     */
    pub fn new(id: i64, name: String, created_at: DateTime<Utc>, created_by: String) -> Self {
        MunicipalityDetailType { id, name, created_at, created_by }
    }
}

/**
 * Converts from db query.
 */
impl From<QueryMunicipalityListDbResp> for MunicipalityDetailType {
    fn from(value: QueryMunicipalityListDbResp) -> Self {
        MunicipalityDetailType::new(value.0, value.1, value.2, value.3)
    }
}

/***************** Municipality:add models *********************/
#[derive(Debug)]
pub struct MunicipalityAddInputType {
    /**
     * municipality id.
     */
    pub id: i64,
    /**
     * Name of the municipality.
     */
    pub name: String,
    /**
     * The user who creates the municipality.
     */
    pub created_by: String,
}

impl MunicipalityAddInputType {
    /**
     * Creates a new `MunicipalityAddInputType`.
     *
     * # Arguments
     * `id`: The unique identifier for the municipality.
     * `name`: The name of the municipality.
     * `created_by`: The user who creates the municipality.
     *
     * # Returns
     * A new instance of `MunicipalityAddInputType`.
     */
    pub fn new(id: i64, name: String, created_by: String) -> Self {
        MunicipalityAddInputType { id, name, created_by }
    }

    /**
     * Validates the municipality input.
     *
     * # Returns
     * A Result containing `MunicipalityAddInputType` or an `ApplicationError`.
     */
    pub fn validate(self) -> Result<Self, ApplicationError> {
        if self.id < 0 {
            return Err(ApplicationError::new(ErrorType::Validation, "Municipality ID must be non-negative".to_string()));
        }
        if self.name.is_empty() {
            return Err(ApplicationError::new(ErrorType::Validation, "Municipality name cannot be empty".to_string()));
        }
        Ok(self)
    }
}

/**
 * Converts from request data and jwt claim name to `MunicipalityAddInputType`.
 */
impl From<(&web::Json<MunicipalityAddRequest>, String)> for MunicipalityAddInputType {
    fn from(from: (&web::Json<MunicipalityAddRequest>, String)) -> Self {
        MunicipalityAddInputType::new(from.0.id, from.0.name.clone(), from.1.clone())
    }
}

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

    /**
     * Validates the statistic input.
     *
     * # Returns
     * A Result containing `StatisticAddInputType` or an `ApplicationError`.
     */
    pub fn validate(self) -> Result<Self, ApplicationError> {
        if self.id < 0 {
            return Err(ApplicationError::new(ErrorType::Validation, "Statistic ID must be non-negative".to_string()));
        }
        if self.name.is_empty() {
            return Err(ApplicationError::new(ErrorType::Validation, "Statistic name cannot be empty".to_string()));
        }
        Ok(self)
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

impl ValuesListInputType {
    /**
     * Creates a new `ValuesListInputType`.
     *
     * # Arguments
     * `id_municipality`: Optional municipality ID to filter the values.
     * `id_statistic`: Optional statistic ID to filter the values.
     * `year`: Optional year to filter the values.
     *
     * # Returns
     * A new instance of `ValuesListInputType`.
     */
    #[allow(dead_code)]
    pub fn new(id_municipality: Option<i64>, id_statistic: Option<i64>, year: Option<i64>) -> Self {
        ValuesListInputType { id_municipality, id_statistic, year }
    }

    /**
     * Validates the values list input.
     *
     * # Returns
     * A Result containing `ValuesListInputType` or an `ApplicationError`.
     */
    pub fn validate(self) -> Result<Self, ApplicationError> {
        if let Some(id) = self.id_municipality {
            if id < 0 {
                return Err(ApplicationError::new(ErrorType::Validation, "Municipality ID must be non-negative".to_string()));
            }
        }
        if let Some(id) = self.id_statistic {
            if id < 0 {
                return Err(ApplicationError::new(ErrorType::Validation, "Statistic ID must be non-negative".to_string()));
            }
        }
        if let Some(year) = self.year {
            if year < 0 {
                return Err(ApplicationError::new(ErrorType::Validation, "Year must be non-negative".to_string()));
            }
        }
        Ok(self)
    }
}

/**
 * Converts from `web::Json<ValuesListRequest>` to `ValuesListInputType`.
 */
impl From<&web::Json<ValuesListRequest>> for ValuesListInputType {
    fn from(request: &web::Json<ValuesListRequest>) -> Self {
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

/***************** Values:add models *********************/
#[derive(Debug, Clone)]
pub struct ValuesAddUpdateInputType {
    /**
     * The ID of the municipality.
     */
    pub id_municipality: i64,
    /**
     * The ID of the statistic.
     */
    pub id_statistic: i64,
    /**
     * The value associated with the statistic.
     */
    pub value: Decimal,
    /**
     * The year of the statistic.
     */
    pub year: i64,
    /**
     * The user who creates/updates the value.
     */
    pub claim_name: String,
}

impl ValuesAddUpdateInputType {
    /**
     * Creates a new `ValuesAddUpdateInputType`.
     *
     * # Arguments
     * `id_municipality`: The ID of the municipality.
     * `id_statistic`: The ID of the statistic.
     * `value`: The value associated with the statistic.
     * `year`: The year of the statistic.
     * `created_by`: The user who creates the value.
     *
     * # Returns
     * A new instance of `ValuesAddUpdateInputType`.
     */
    pub fn new(id_municipality: i64, id_statistic: i64, value: Decimal, year: i64, claim_name: String) -> Self {
        ValuesAddUpdateInputType { id_municipality, id_statistic, value, year, claim_name }
    }

    /**
     * Validates the values add input.
     *
     * # Returns
     * A Result containing `ValuesAddInputType` or an `ApplicationError`.
     */
    pub fn validate(self) -> Result<Self, ApplicationError> {
        if self.id_municipality < 0 {
            return Err(ApplicationError::new(ErrorType::Validation, "Municipality ID must be non-negative".to_string()));
        }
        if self.id_statistic < 0 {
            return Err(ApplicationError::new(ErrorType::Validation, "Statistic ID must be non-negative".to_string()));
        }
        if self.year < 0 {
            return Err(ApplicationError::new(ErrorType::Validation, "Year must be non-negative".to_string()));
        }
        Ok(self)
    }
}

impl From<(&web::Json<ValuesAddUpdateRequest>, String)> for ValuesAddUpdateInputType {
    fn from(from: (&web::Json<ValuesAddUpdateRequest>, String)) -> Self {
        ValuesAddUpdateInputType::new(from.0.municipality_id, from.0.statistic_id, from.0.value, from.0.year, from.1.clone())
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

    /**
     * Validates the pagination input.
     *
     * # Returns
     * A Result containing `PaginationInput` or an `ApplicationError`.
     */
    pub fn validate(self) -> Result<Self, ApplicationError> {
        if self.start_index < 0 {
            return Err(ApplicationError::new(ErrorType::Validation, "Start index must be non-negative".to_string()));
        }
        if self.page_size <= 0 {
            return Err(ApplicationError::new(ErrorType::Validation, "Page size must be greater than zero".to_string()));
        }
        if self.page_size > MAX_PAGE_SIZE {
            return Err(ApplicationError::new(ErrorType::Validation, format!("Page size must not exceed {MAX_PAGE_SIZE}")));
        }
        Ok(self)
    }
}

/**
 * Converts from request query parameters to `PaginationInput`.
 */
impl From<&Query<PaginationQuery>> for PaginationInput {
    fn from(query: &Query<PaginationQuery>) -> Self {
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_pagination_input_validation() {
        let valid_input = PaginationInput::new(0, 10).validate();
        assert!(valid_input.is_ok());

        let negative_start_index = PaginationInput::new(-1, 10).validate();
        assert!(negative_start_index.is_err());

        let zero_page_size = PaginationInput::new(0, 0).validate();
        assert!(zero_page_size.is_err());

        let large_page_size = PaginationInput::new(0, 101).validate();
        assert!(large_page_size.is_err());
    }

    #[test]
    fn test_add_statistic_input_validation() {
        let valid_input = StatisticAddInputType::new(1, "Test Statistic".to_string(), "user1".to_string()).validate();
        assert!(valid_input.is_ok());

        let negative_id = StatisticAddInputType::new(-1, "Test Statistic".to_string(), "user1".to_string()).validate();
        assert!(negative_id.is_err());

        let empty_name = StatisticAddInputType::new(1, "".to_string(), "user1".to_string()).validate();
        assert!(empty_name.is_err());
    }

    #[test]
    fn test_values_list_input_validation() {
        let valid_input = ValuesListInputType::new(Some(1), Some(2), Some(2023)).validate();
        assert!(valid_input.is_ok());

        let negative_municipality_id = ValuesListInputType::new(Some(-1), Some(2), Some(2023)).validate();
        assert!(negative_municipality_id.is_err());

        let negative_statistic_id = ValuesListInputType::new(Some(1), Some(-2), Some(2023)).validate();
        assert!(negative_statistic_id.is_err());

        let negative_year = ValuesListInputType::new(Some(1), Some(2), Some(-2023)).validate();
        assert!(negative_year.is_err());
    }

    #[test]
    fn test_municipality_add_input_validation() {
        let valid_input = MunicipalityAddInputType::new(1, "Test Municipality".to_string(), "user1".to_string()).validate();
        assert!(valid_input.is_ok());

        let negative_id = MunicipalityAddInputType::new(-1, "Test Municipality".to_string(), "user1".to_string()).validate();
        assert!(negative_id.is_err());

        let empty_name = MunicipalityAddInputType::new(1, "".to_string(), "user1".to_string()).validate();
        assert!(empty_name.is_err());
    }

    #[test]
    fn test_values_add_update_input_validation() {
        let valid_input = ValuesAddUpdateInputType::new(1, 2, Decimal::new(100, 2), 2023, "user1".to_string()).validate();
        assert!(valid_input.is_ok());

        let negative_municipality_id = ValuesAddUpdateInputType::new(-1, 2, Decimal::new(100, 2), 2023, "user1".to_string()).validate();
        assert!(negative_municipality_id.is_err());

        let negative_statistic_id = ValuesAddUpdateInputType::new(1, -2, Decimal::new(100, 2), 2023, "user1".to_string()).validate();
        assert!(negative_statistic_id.is_err());

        let negative_year = ValuesAddUpdateInputType::new(1, 2, Decimal::new(100, 2), -2023, "user1".to_string()).validate();
        assert!(negative_year.is_err());
    }
}
