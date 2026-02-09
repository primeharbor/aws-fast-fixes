# CloudWatch Logs Insights Queries for Amazon Bedrock Usage Tracking

This document provides pre-built CloudWatch Logs Insights queries for analyzing Amazon Bedrock model invocation logs. Use these queries to track usage, analyze costs, and monitor token consumption patterns across users.

## Prerequisites

1. Bedrock logging must be enabled using [`enable-bedrock-logging.py`](enable-bedrock-logging.py)
2. Bedrock model invocations must be generating logs to CloudWatch
3. Access to CloudWatch Logs Insights in the AWS Console

## How to Use These Queries

### Running Queries in AWS Console

1. Navigate to **CloudWatch > Logs > Insights**
2. Select your log group (e.g., `/aws/bedrock/modelinvocations`)
3. Copy one of the queries below
4. Paste into the query editor
5. Select a time range (e.g., Last 1 hour, Last 7 days, Custom)
6. Click **Run query**

### Exporting Results

After running a query:
- Click **Export results** to download as CSV
- Use **Add to dashboard** to create visualizations
- Click **Save** to save the query for future use

### Cost Information

CloudWatch Logs Insights charges **$0.005 per GB** of data scanned. This is cost-effective for periodic analysis. Running these queries on typical Bedrock usage logs costs pennies per query.

---

## Queries

### 1. Total Usage by User

**Purpose**: View aggregate token consumption grouped by user (identity.arn). Shows input tokens, cache tokens, output tokens, and total invocation count per user.

**Use Case**: Monthly cost allocation, identifying high-volume users, capacity planning

```
fields identity.arn as User,
       input.inputTokenCount as InputTokens,
       input.cacheReadInputTokenCount as CacheReadTokens,
       input.cacheWriteInputTokenCount as CacheWriteTokens,
       output.outputTokenCount as OutputTokens
| stats sum(InputTokens) as TotalInput,
        sum(CacheReadTokens) as TotalCacheRead,
        sum(CacheWriteTokens) as TotalCacheWrite,
        sum(OutputTokens) as TotalOutput,
        count() as InvocationCount by User
| sort TotalOutput desc
```

**Output Columns**:
- `User` - The IAM identity (role/user ARN)
- `TotalInput` - Total input tokens consumed
- `TotalCacheRead` - Total cache read tokens (cache hits)
- `TotalCacheWrite` - Total cache write tokens (cache population)
- `TotalOutput` - Total output tokens generated
- `InvocationCount` - Number of API calls made

---

### 2. Token Breakdown by Type

**Purpose**: Aggregate view of all token consumption across all users, separated by token type.

**Use Case**: Overall usage trends, capacity monitoring, comparing token types

```
fields @timestamp,
       input.inputTokenCount as InputTokens,
       input.cacheReadInputTokenCount as CacheReadTokens,
       input.cacheWriteInputTokenCount as CacheWriteTokens,
       output.outputTokenCount as OutputTokens
| stats sum(InputTokens) as TotalInput,
        sum(CacheReadTokens) as TotalCacheRead,
        sum(CacheWriteTokens) as TotalCacheWrite,
        sum(OutputTokens) as TotalOutput
```

**Output Columns**:
- `TotalInput` - Sum of all input tokens
- `TotalCacheRead` - Sum of all cache read tokens
- `TotalCacheWrite` - Sum of all cache write tokens
- `TotalOutput` - Sum of all output tokens

---

### 3. Top 10 Users by Token Count

**Purpose**: Identify the highest token consumers across all token types.

**Use Case**: Finding top consumers for cost allocation, identifying power users, detecting anomalies

```
fields identity.arn as User,
       input.inputTokenCount + input.cacheReadInputTokenCount + input.cacheWriteInputTokenCount + output.outputTokenCount as TotalTokens
| stats sum(TotalTokens) as TotalTokenCount, count() as Invocations by User
| sort TotalTokenCount desc
| limit 10
```

**Output Columns**:
- `User` - The IAM identity
- `TotalTokenCount` - Combined total of all token types
- `Invocations` - Number of API calls

**Note**: Modify `limit 10` to show more or fewer users (e.g., `limit 20` for top 20)

---

### 4. Usage Over Time (Hourly)

**Purpose**: Time-series view of token consumption with hourly granularity.

**Use Case**: Identifying usage patterns, detecting spikes, trend analysis

```
fields @timestamp,
       input.inputTokenCount as Input,
       output.outputTokenCount as Output
| stats sum(Input) as InputTokens,
        sum(Output) as OutputTokens by bin(1h)
```

**Output Columns**:
- `bin(1h)` - Time bucket (hourly)
- `InputTokens` - Total input tokens for this hour
- `OutputTokens` - Total output tokens for this hour

**Customization**: Change `bin(1h)` to:
- `bin(15m)` - 15-minute intervals
- `bin(1d)` - Daily aggregation
- `bin(1w)` - Weekly aggregation

---

### 5. Cache Efficiency Analysis

**Purpose**: Calculate cache hit percentage per user to measure prompt caching effectiveness.

**Use Case**: Evaluating cache performance, identifying users benefiting from caching, optimizing prompt strategies

```
fields identity.arn as User,
       input.cacheReadInputTokenCount as CacheRead,
       input.cacheWriteInputTokenCount as CacheWrite,
       input.inputTokenCount as Input
| stats sum(CacheRead) as TotalCacheReads,
        sum(CacheWrite) as TotalCacheWrites,
        sum(Input) as TotalInput by User
| fields User, TotalCacheReads, TotalCacheWrites,
         (TotalCacheReads * 100.0 / (TotalCacheReads + TotalInput)) as CacheHitPercent
| sort CacheHitPercent desc
```

**Output Columns**:
- `User` - The IAM identity
- `TotalCacheReads` - Total tokens read from cache
- `TotalCacheWrites` - Total tokens written to cache
- `CacheHitPercent` - Percentage of requests served from cache

**Interpretation**:
- Higher `CacheHitPercent` = Better cache utilization = Lower costs
- Users with 0% cache hit may benefit from enabling prompt caching

---

### 6. Cost Estimation (Claude Sonnet 4.5)

**Purpose**: Calculate estimated AWS costs per user based on Bedrock token pricing.

**Use Case**: Monthly billing estimates, cost allocation, budget tracking

```
# Pricing: Input=$3/MTok, Output=$15/MTok, CacheWrite=$3.75/MTok, CacheRead=$0.30/MTok
fields identity.arn as User,
       input.inputTokenCount as Input,
       input.cacheReadInputTokenCount as CacheRead,
       input.cacheWriteInputTokenCount as CacheWrite,
       output.outputTokenCount as Output
| stats sum(Input) as TotalInput,
        sum(CacheRead) as TotalCacheRead,
        sum(CacheWrite) as TotalCacheWrite,
        sum(Output) as TotalOutput by User
| fields UserName,
         (TotalInput * 3.0 / 1000000) as InputCost,
         (TotalCacheRead * 0.30 / 1000000) as CacheReadCost,
         (TotalCacheWrite * 3.75 / 1000000) as CacheWriteCost,
         (TotalOutput * 15.0 / 1000000) as OutputCost,
         (TotalInput * 3.0 / 1000000) + (TotalCacheRead * 0.30 / 1000000) + (TotalCacheWrite * 3.75 / 1000000) + (TotalOutput * 15.0 / 1000000) as TotalCost
| sort TotalCost desc
```

**Output Columns**:
- `User` - The IAM identity
- `TotalCost` - Total estimated cost in USD
- `InputCost` - Cost from input tokens
- `CacheReadCost` - Cost from cache read tokens
- `CacheWriteCost` - Cost from cache write tokens
- `OutputCost` - Cost from output tokens

**Pricing Assumptions** (Claude Sonnet 4.5):
- Input tokens: $3.00 per million tokens
- Output tokens: $15.00 per million tokens
- Cache write tokens: $3.75 per million tokens
- Cache read tokens: $0.30 per million tokens

**Note**: Update pricing values for other models (Opus, Haiku, etc.). See [AWS Bedrock Pricing](https://aws.amazon.com/bedrock/pricing/) for current rates.

---

### 7. Usage by Model

**Purpose**: Break down token consumption by model ID.

**Use Case**: Multi-model environments, comparing model usage, capacity planning per model

```
fields modelId,
       input.inputTokenCount + output.outputTokenCount as TotalTokens
| stats sum(TotalTokens) as TokenCount, count() as Invocations by modelId
| sort TokenCount desc
```

**Output Columns**:
- `modelId` - The Bedrock model ID or inference profile ARN
- `TokenCount` - Total tokens consumed by this model
- `Invocations` - Number of times this model was invoked

**Note**: This shows which models are used most heavily in your account.

---

### 8. Recent Invocations by User

**Purpose**: View the most recent API calls with details about user, model, tokens, and request ID.

**Use Case**: Real-time monitoring, debugging, auditing, investigating specific requests

```
fields @timestamp,
       identity.arn as User,
       modelId,
       input.inputTokenCount as Input,
       output.outputTokenCount as Output,
       requestId
| sort @timestamp desc
| limit 100
```

**Output Columns**:
- `@timestamp` - When the invocation occurred
- `User` - The IAM identity
- `modelId` - Model that was invoked
- `Input` - Input tokens for this request
- `Output` - Output tokens for this request
- `requestId` - Unique request identifier for debugging

**Customization**: Change `limit 100` to see more or fewer recent invocations.

---

## Available Fields Reference

Based on the Bedrock model invocation log structure ([`sample-event.json`](sample-event.json)), the following fields are available for querying:

### Top-Level Fields
- `@timestamp` - Log event timestamp
- `timestamp` - Invocation timestamp (ISO 8601 format)
- `accountId` - AWS account ID
- `region` - AWS region where invocation occurred
- `requestId` - Unique request identifier
- `operation` - API operation (e.g., `InvokeModel`, `InvokeModelWithResponseStream`)
- `modelId` - Model ARN or inference profile ARN
- `inferenceRegion` - Region where inference was performed
- `schemaType` - Log schema type (`ModelInvocationLog`)
- `schemaVersion` - Log schema version

### Identity Fields
- `identity.arn` - IAM principal ARN (user/role making the request)

### Input Fields
- `input.inputContentType` - Content type of input (e.g., `application/json`)
- `input.inputBodyS3Path` - S3 path to large input data (if applicable)
- `input.inputTokenCount` - Number of input tokens
- `input.cacheReadInputTokenCount` - Tokens served from cache (cache hits)
- `input.cacheWriteInputTokenCount` - Tokens written to cache (cache population)

### Output Fields
- `output.outputContentType` - Content type of output
- `output.outputBodyJson` - JSON output body (array of message events for streaming)
- `output.outputTokenCount` - Number of output tokens generated

### Invocation Metrics (in outputBodyJson)
The `output.outputBodyJson` array contains streaming response chunks. The final `message_stop` event includes:
- `amazon-bedrock-invocationMetrics.inputTokenCount`
- `amazon-bedrock-invocationMetrics.outputTokenCount`
- `amazon-bedrock-invocationMetrics.invocationLatency` - Total latency in milliseconds
- `amazon-bedrock-invocationMetrics.firstByteLatency` - Time to first byte in milliseconds
- `amazon-bedrock-invocationMetrics.cacheReadInputTokenCount`
- `amazon-bedrock-invocationMetrics.cacheWriteInputTokenCount`

**Note**: Most queries use the top-level token count fields (`input.*` and `output.*`) rather than parsing `outputBodyJson`.

---

## Tips and Best Practices

### Query Performance
- **Use specific time ranges**: Shorter time ranges scan less data and cost less
- **Filter early**: Add `| filter` clauses early in the query to reduce data processing
- **Limit results**: Use `| limit N` to cap the number of rows returned

### Customizing Queries
- **Filter by user**: Add `| filter identity.arn like "arn:aws:sts::123456789:assumed-role/MyRole"`
- **Filter by model**: Add `| filter modelId like "claude-sonnet"`
- **Filter by time**: Add `| filter @timestamp >= (now() - 1h)` for last hour

### Cost Optimization
- **Cache efficiency**: Focus on Query #5 to optimize cache usage and reduce costs
- **Schedule queries**: Run cost estimation queries weekly/monthly instead of real-time
- **Export to S3**: For long-term analysis, export query results to S3 instead of re-running queries

### Common Modifications

**Filter to a specific user**:
```
fields identity.arn as User, ...
| filter User like "john.doe@example.com"
```

**Show only high-cost invocations** (>1000 output tokens):
```
fields @timestamp, identity.arn, output.outputTokenCount
| filter output.outputTokenCount > 1000
| sort output.outputTokenCount desc
```

**Daily aggregation instead of hourly**:
```
stats sum(input.inputTokenCount) as Input by bin(1d)
```

---

## Troubleshooting

**No results returned**:
- Verify Bedrock logging is enabled and configured correctly
- Check that you've selected the correct log group
- Ensure the time range includes periods with Bedrock activity
- Verify your IAM permissions allow reading CloudWatch Logs

**Query syntax errors**:
- Ensure all field names match exactly (case-sensitive)
- Verify pipe `|` characters separate query stages
- Check that aggregation functions (`sum`, `count`, `stats`) are used correctly

**Unexpected results**:
- Compare field names with [`sample-event.json`](sample-event.json)
- Check for null/missing values: Add `| filter fieldname != ""` to exclude empties
- Verify pricing assumptions in cost estimation query match your model

---

## Additional Resources

- [AWS CloudWatch Logs Insights Query Syntax](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html)
- [Amazon Bedrock Model Invocation Logging](https://docs.aws.amazon.com/bedrock/latest/userguide/model-invocation-logging.html)
- [Amazon Bedrock Pricing](https://aws.amazon.com/bedrock/pricing/)
- [Claude Prompt Caching Documentation](https://docs.anthropic.com/claude/docs/prompt-caching)

---

## Contributing

To add new queries or improve existing ones:
1. Test queries thoroughly with real Bedrock logs
2. Document the purpose, use case, and output columns
3. Include any pricing assumptions or customization options
4. Submit changes via pull request or issue
