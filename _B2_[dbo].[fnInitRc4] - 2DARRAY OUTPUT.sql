USE [TestDecryption];
GO

SET NOCOUNT ON;

DECLARE

    @family_guid BINARY(16)
  , @objid       BINARY(4)
  , @subobjid    BINARY(2)
  , @RC4Key      BINARY(20);

SELECT @family_guid = 0x2556AD936B8C3947876B08258F5EB3C3
/*
= CONVERT(BINARY(16), [DRS].[family_guid])
FROM [sys].[database_recovery_status] AS [DRS]
WHERE [DRS].[database_id] = DB_ID(); 
*/

/* Convert object ID to little-endian binary(4): */
SELECT @objid = 0x6BD9DF19 /* = CONVERT(BINARY(4), REVERSE(CONVERT(BINARY(4), OBJECT_ID('dbo.p_TestEncryption_Short')))); */
SET @subobjid = 0x0100

SELECT @RC4Key = HASHBYTES('SHA1', @family_guid + @objid + @subobjid); /* = 0xCDE2207D4CE12EFD5C5161D98A7752B03BBF45B9 */ 
DROP TABLE IF EXISTS [#Initialized4C]
CREATE TABLE [#Initialized4C] ([Rn] TINYINT NOT NULL, [v] TINYINT NOT NULL);

INSERT INTO [#Initialized4C] ([Rn], [v])
SELECT [Rn], [v] FROM [dbo].[fnInitRc4](@RC4Key)

SELECT [Rn], [v] FROM [#Initialized4C] 
ORDER BY [Rn]

/* [#Initialized4C] in 2D-array form after initialization (shuffling): */
SELECT
    [0], [1], [2], [3], [4], [5], [6], [7], [8], [9], [10], [11], [12], [13], [14], [15]
FROM (
    SELECT
        [v],
        (ROW_NUMBER() OVER (ORDER BY [Rn]) - 1) / 16 AS [Row],
        (ROW_NUMBER() OVER (ORDER BY [Rn]) - 1) % 16 AS [Col]
    FROM
        [#Initialized4C]
) AS [t]
PIVOT (
    MAX([v])
    FOR [Col] IN ([0], [1], [2], [3], [4], [5], [6], [7], [8], [9], [10], [11], [12], [13], [14], [15])
) AS [p]

/*
SELECT [Rn], [v] FROM [#Initialized4C] 
WHERE [Rn] IN (1, 19, 176)
ORDER BY [Rn]
--SELECT (99 + 176) % 256 = 19
*/