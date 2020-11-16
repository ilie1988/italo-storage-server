#pragma once

#include "italo_logger.h"

struct pow_difficulty_t;

namespace italo {

namespace dns {

std::vector<pow_difficulty_t> query_pow_difficulty(std::error_code& ec);

void check_latest_version();

} // namespace dns
} // namespace italo
