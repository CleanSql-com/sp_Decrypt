USE [TestDecryption];
GO

/* https://www.sqlteam.com/forums/topic.asp?TOPIC_ID=76258 */
/* This function is used to initialize the seed for the RC4 algorithm: */
/* Testing:
DECLARE

    @family_guid BINARY(16)
  , @objid       BINARY(4)
  , @subobjid    BINARY(2)
  , @imageval    VARBINARY(MAX)
  , @RC4Key      BINARY(20);

SELECT @family_guid = CONVERT(BINARY(16), [DRS].[family_guid])
FROM [sys].[database_recovery_status] AS [DRS]
WHERE [DRS].[database_id] = DB_ID(); --> = 0x2556AD936B8C3947876B08258F5EB3C3

/* Convert object ID to little-endian binary(4): */
SELECT @objid = CONVERT(BINARY(4), REVERSE(CONVERT(BINARY(4), OBJECT_ID('dbo.p_TestEncryption_Short')))); --> = 0x6BD9DF19	 
SET @subobjid	 = 0x0100

SELECT @RC4Key = HASHBYTES('SHA1', @family_guid + @objid + @subobjid); --> = 0xCDE2207D4CE12EFD5C5161D98A7752B03BBF45B9
SELECT [Rn], [v] FROM [dbo].[fnInitRc4](@RC4Key)
*/

CREATE OR ALTER FUNCTION [dbo].[fnInitRc4] (@RC4Key VARCHAR(20))
RETURNS @Output TABLE ([Rn] TINYINT NOT NULL, [v] TINYINT NOT NULL)
AS
BEGIN
    DECLARE @KeyTbl TABLE ([Rn] TINYINT NOT NULL, [v] TINYINT NOT NULL);
    DECLARE @Rn        SMALLINT
          , @RC4KeyLen TINYINT;
    SELECT @Rn = 0, @RC4KeyLen = LEN(@RC4Key);

    WHILE @Rn <= 255
    BEGIN
        INSERT @KeyTbl ([Rn], [v]) VALUES (@Rn, ASCII(SUBSTRING(@RC4Key, @Rn % @RC4KeyLen + 1, 1)));
        INSERT @Output ([Rn], [v]) VALUES (@Rn, @Rn);
        SELECT @Rn = @Rn + 1;
    END;


    DECLARE @pwd TINYINT  = 0
          , @tmp SMALLINT = 0 /* has to be SMALLINT because of this line: SELECT @mod = (@mod + [b].[v] + [k].[v]) % 256 */
          , @mod TINYINT  = 0 
          , @idx TINYINT  = 0
          , @new TINYINT  = 0;

    SELECT @Rn = 0;

    WHILE @Rn <= 255
    BEGIN
        SELECT @pwd = [v] FROM @KeyTbl WHERE [Rn] = @Rn;
        SELECT @tmp = [v] FROM @Output WHERE [Rn] = @Rn;
        SELECT @idx = (@pwd + @tmp + @mod) % 256
        FROM @Output AS [o]
        INNER JOIN @KeyTbl AS [k]
            ON [k].[Rn] = [o].[Rn]
        WHERE [o].[Rn] = @Rn;

        SELECT @new = [v] FROM @Output WHERE [Rn] = @idx;
        /*
        PRINT (CONCAT(@Rn, ' (@pwd + @tmp + @mod) % 256: (', @pwd, ' + ', @tmp, ' + ', @mod, ')%256 = ', (@pwd + @tmp + @mod) % 256));
        PRINT (CONCAT(@Rn, ' @new: ', @new));
        */

        UPDATE @Output SET [v] = @new WHERE [Rn] = @Rn;
        UPDATE @Output SET [v] = @tmp WHERE [Rn] = @idx;
        SELECT @mod = @idx;
        SELECT @Rn = @Rn + 1;
    END;
    RETURN;
END;