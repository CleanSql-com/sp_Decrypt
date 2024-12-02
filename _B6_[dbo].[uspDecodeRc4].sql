USE [TestDecryption];
GO

/* https://www.sqlteam.com/forums/topic.asp?TOPIC_ID=76258 */
/* This procedure [uspDecodeRc4] decrypts RC4 encrypted objects only: */

CREATE OR ALTER PROCEDURE [dbo].[uspDecodeRc4] (@RC4Key BINARY(20), @EncryptedText VARBINARY(MAX), @ObjectId INT, @DebugMode BIT = 0)
AS
BEGIN

    SET NOCOUNT ON;
    DECLARE @Rn                        INT
          , @idx                       SMALLINT
          , @idx_new                   SMALLINT
          , @tmp                       TINYINT
          , @EncryptionKeyChar         SMALLINT
          , @DecryptedCharInt          INT
          , @PreviousDecryptedCharInt  INT
          , @DecryptedLine             NVARCHAR(MAX)
          , @DecryptedLineStartPointer INT;

    IF OBJECT_ID('tempdb.dbo.#CypherBox', 'U') IS NULL
        CREATE TABLE [#CypherBox] ([Rn] TINYINT NOT NULL PRIMARY KEY CLUSTERED, [v] TINYINT NOT NULL);

    IF OBJECT_ID('tempdb.dbo.#StagingCharTable', 'U') IS NULL
        CREATE TABLE [#StagingCharTable]
        (
            [Id]            INT      NOT NULL IDENTITY(1, 1) PRIMARY KEY CLUSTERED
          , [Index]         INT      NOT NULL UNIQUE
          , [DecryptedChar] NCHAR(1) NOT NULL
        );

    IF OBJECT_ID('tempdb.dbo.#ObjectDefinition', 'U') IS NULL
        CREATE TABLE [#ObjectDefinition] ([LineId] INT PRIMARY KEY CLUSTERED IDENTITY(1, 1), [DecryptedLine] NVARCHAR(MAX) NOT NULL);

    IF OBJECT_ID('tempdb.dbo.#DebugTable', 'U') IS NULL
        CREATE TABLE [#DebugTable]
        (
            [Id]            INT NOT NULL IDENTITY(1, 1) PRIMARY KEY CLUSTERED
          , [Index]         INT NOT NULL UNIQUE
          , [CypherTextNum] INT NOT NULL
          , [EncryptionKey] INT NOT NULL
          , [ClearTextNum]  INT NOT NULL
        );

    INSERT [#CypherBox] ([Rn], [v]) SELECT [Rn], [v] FROM [dbo].[fnInitRc4](@RC4Key);
    --SELECT [Rn], [v] FROM [dbo].[fnInitRc4](0xCDE2207D4CE12EFD5C5161D98A7752B03BBF45B9)

    SELECT @Rn = 1, @idx = 0, @idx_new = 0, @DecryptedLineStartPointer = 1;

    WHILE @Rn <= DATALENGTH(@EncryptedText)
    BEGIN
        /* save previously decrypted charcter if there is one: */
        IF (@Rn > 1 AND @DecryptedCharInt IS NOT NULL)
        BEGIN
            SELECT @PreviousDecryptedCharInt = @DecryptedCharInt;
        END;

        SELECT @idx = (@idx + 1) % 256;
        SELECT @tmp = [v] FROM [#CypherBox] WHERE [Rn] = @idx;
        SELECT @idx_new = (@idx_new + [v]) % 256 FROM [#CypherBox] WHERE [Rn] = @idx;

        /* PRINT (CONCAT('@idx: ', @idx, '; @idx_new: ', @idx_new, '; @tmp: ', @tmp)); */

        UPDATE [b1]
        SET [b1].[v] = [b2].[v] /* (SELECT [cb].[v] FROM [#CypherBox] AS [cb] WHERE [cb].[Rn] = @idx_new) */
        FROM [#CypherBox] AS [b1]
        JOIN [#CypherBox] AS [b2]
            ON [b2].[Rn] = @idx_new
        WHERE [b1].[Rn] = @idx;

        UPDATE [#CypherBox] SET [v] = @tmp WHERE [Rn] = @idx_new;

        SELECT @EncryptionKeyChar = [v] FROM [#CypherBox] WHERE [Rn] = @idx;
        SELECT @EncryptionKeyChar = (@EncryptionKeyChar + [v]) % 256 FROM [#CypherBox] WHERE [Rn] = @idx_new;
        SELECT @EncryptionKeyChar = [v] FROM [#CypherBox] WHERE [Rn] = @EncryptionKeyChar;
        SELECT @DecryptedCharInt = ASCII(SUBSTRING(@EncryptedText, @Rn, 1)) ^ @EncryptionKeyChar;
        
        IF (@DebugMode = 1)
        BEGIN
            INSERT INTO [#DebugTable] ([Index], [CypherTextNum], [EncryptionKey], [ClearTextNum])
            VALUES (@Rn, ASCII(SUBSTRING(@EncryptedText, @Rn, 1)), @EncryptionKeyChar, @DecryptedCharInt);
        END;

        IF ((@Rn % 2 = 0) AND @DecryptedCharInt = 0 AND @PreviousDecryptedCharInt > 31) /* ASCII Char Found */
        BEGIN
            INSERT INTO [#StagingCharTable] ([Index], [DecryptedChar]) VALUES (@Rn, NCHAR(@PreviousDecryptedCharInt));
        END;

        IF ((@Rn % 2 = 0) AND @DecryptedCharInt > 0 AND @PreviousDecryptedCharInt > 0) /* Unicode Char Found */
        BEGIN
            INSERT INTO [#StagingCharTable] ([Index], [DecryptedChar])
            VALUES (@Rn, NCHAR(CONVERT(VARBINARY(2), (@DecryptedCharInt * 0x100) + @PreviousDecryptedCharInt)));
        END;

        IF ((@Rn % 2 = 0) AND @DecryptedCharInt = 0 AND @PreviousDecryptedCharInt = 10) /* CRLF Sequence Detected */
        BEGIN
            SELECT @DecryptedLine = STRING_AGG([ckt].[DecryptedChar], '')
            FROM [#StagingCharTable] AS [ckt]
            WHERE [ckt].[Index] > @DecryptedLineStartPointer
            AND   [ckt].[Index] <= @Rn;

            SELECT @DecryptedLine = REPLACE(REPLACE(@DecryptedLine, CHAR(13), ''), CHAR(10), '');

            IF (LEN(@DecryptedLine) > 0)
            BEGIN
                PRINT (@DecryptedLine);
                INSERT INTO [#ObjectDefinition] ([DecryptedLine]) VALUES (@DecryptedLine);
                SET @DecryptedLine = NULL;

                SET @DecryptedLineStartPointer = @Rn;
            END;
        END;
        SELECT @Rn = @Rn + 1;
    END;

    /* if there are any leftover chars in the [#StagingCharTable] after @DecryptedLineStartPointer without CRLF at the end save them: */
    IF EXISTS (SELECT 1 FROM [#StagingCharTable] WHERE [Index] > @DecryptedLineStartPointer)
    BEGIN
        SELECT @DecryptedLine = STRING_AGG([ckt].[DecryptedChar], '')
        FROM [#StagingCharTable] AS [ckt]
        WHERE [ckt].[Index] > @DecryptedLineStartPointer;

        SELECT @DecryptedLine = REPLACE(REPLACE(@DecryptedLine, CHAR(13), ''), CHAR(10), '');

        IF (LEN(@DecryptedLine) > 0)
        BEGIN
            PRINT (@DecryptedLine);
            INSERT INTO [#ObjectDefinition] ([DecryptedLine]) VALUES (@DecryptedLine);
            SET @DecryptedLine = NULL;
        END;
    END;

    SELECT @ObjectId AS [ObjectId], [LineId], [DecryptedLine] FROM [#ObjectDefinition] ORDER BY [LineId];

    IF (@DebugMode = 1)
    BEGIN
        WITH [cte]
        AS (SELECT
                   [dt].[CypherTextNum]
                 , CHAR([dt].[CypherTextNum]) AS [CypherTextChar]
                 , [dt].[EncryptionKey]
                 , CHAR([dt].[EncryptionKey]) AS [EncryptionKeyChar]
                 , [dt].[ClearTextNum]
                 , CASE
                       WHEN (   ([dt].[Index] % 2 = 1)
                         AND    [dt].[ClearTextNum] > 31
                         AND    LEAD([dt].[ClearTextNum], 1, 0) OVER (ORDER BY [dt].[Index]) = 0
                            ) THEN CHAR([dt].[ClearTextNum])
                       WHEN (   ([dt].[Index] % 2 = 1)
                         AND    [dt].[ClearTextNum] > 0
                         AND    LEAD([dt].[ClearTextNum], 1, 0) OVER (ORDER BY [dt].[Index]) > 0
                            ) THEN --'Unicode'
                           NCHAR(CONVERT(VARBINARY(2), (LEAD([dt].[ClearTextNum], 1, 0) OVER (ORDER BY [dt].[Index]) * 0x100) + [dt].[ClearTextNum]))
                       ELSE ''
                   END AS [DecryptedCharChar]
            FROM [#DebugTable] AS [dt])
        SELECT
               [cte].[CypherTextNum]
             , [cte].[CypherTextChar]
             , [cte].[EncryptionKey]
             , [cte].[EncryptionKeyChar]
             , [cte].[ClearTextNum]
             , [cte].[DecryptedCharChar]
        FROM [cte]
        WHERE [cte].[ClearTextNum] > 0;
    END;
END;
