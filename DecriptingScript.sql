USE [TestDecryption]
GO

SET NOCOUNT ON;
SET XACT_ABORT ON;

/* ====================================================================================================================== */
/* Author:      CleanSql.com                                                                                              */
/* an extended and hopefully improved version of: 																          */
/* https://www.sqlteam.com/forums/topic.asp?TOPIC_ID=76258																  */
/* https://sqlperformance.com/2016/05/sql-performance/the-internals-of-with-encryption									  */
/* https://en.dirceuresende.com/blog/sql-server-como-recuperar-o-codigo-fonte-de-um-objeto-criptografado-with-encryption/ */
/* https://stackoverflow.com/questions/7670636/how-to-decrypt-stored-procedure-in-sql-server-2008/7671944#7671944		  */
/* Create date: 2023-02-11                                                                                                */
/* Description: Deobfuscate and show the definition of an "encrypted" db object; additionally 						      */
/*              if @CreateDecryptedVersion = 1 is specified it will rename the original encrypted object                  */
/*              by appending "_ENCRYPTED" to the end of the name and create the decrypted version with the original name  */
/* ====================================================================================================================== */
/* Change History:                                                                                                        */
/* ---------------------------------------------------------------------------------------------------------------------- */
/* Date:       User:           Version:  Change:                                                                          */
/* ---------------------------------------------------------------------------------------------------------------------- */
/* 2023-02-11  CleanSql.com    1.0       Created                                                                          */
/* ---------------------------------------------------------------------------------------------------------------------- */
/* ====================================================================================================================== */

/* ====================================================================================================================== */
/* ----------------------------------------- Variable and Temp Table Declarations: -------------------------------------- */
/* ====================================================================================================================== */

/* user varaibles (supply values as needed) */
DECLARE @EncryptedObjectOwnerOrSchema SYSNAME       = N'dbo'
      , @EncryptedObjectName          SYSNAME       = N'p_TestEncryption' /* for example: p_TestEncryption */
      , @CreateDecryptedVersion       BIT           = 0 /* if set to 1 the script will rename the original encrypted object 
                                                          by appending "_ENCRYPTED" to the end of the name 
                                                          and create its decrypted version, with the original name*/
      , @PrintOutObjectDefinition     BIT           = 1;

/* internal variables (no need to supply any values) */
DECLARE @SessionId              INT
      , @ObjectID               INT
      , @ObjectType             NVARCHAR(128)
      , @TriggerOnSchema        SYSNAME
      , @TriggerOnTable         SYSNAME
      , @TriggerForType         NVARCHAR(32)/* Maximum possible length is 22 => SELECT LEN('INSERT, UPDATE, DELETE') */
      , @RealEncryptedObject    NVARCHAR(MAX)
      , @FakePlainTextObject    NVARCHAR(MAX)
      , @FakeEncryptedObject    NVARCHAR(MAX)
      , @RealDecryptedObject    NVARCHAR(MAX)
      , @ObjectDataLength       INT
      , @PointerDecryptedString INT
      , @PointerBeginOfNewLine  INT
      , @CrLf                   CHAR(2)      = CHAR(13) + CHAR(10)
      , @DecryptedLineOfCode    NVARCHAR(MAX);

/* error message varaiables: */
DECLARE @ErrorNumber   INT
      , @ErrorMessage  NVARCHAR(MAX)
      , @ErrorSeverity INT
      , @ErrorState    INT
      , @ErrorLine     INT;

DROP TABLE IF EXISTS [#ObjectDefinition]
CREATE TABLE [#ObjectDefinition]
(
    [LineId] INT PRIMARY KEY CLUSTERED IDENTITY(1,1),
    [DecryptedLineOfCode] NVARCHAR(MAX)
);

/* ====================================================================================================================== */
/* ----------------------------------------- Check if DAC connection is used here: -------------------------------------- */
/* ====================================================================================================================== */

SELECT      @SessionId = ses.session_id
FROM        sys.endpoints AS en
INNER JOIN  sys.dm_exec_sessions ses ON en.endpoint_id = ses.endpoint_id
WHERE       en.name = 'Dedicated Admin Connection';

IF (@@SPID <> (COALESCE(@SessionId, 0)))
BEGIN
    SET @ErrorMessage
        = N'In order to run this script you need to connect using Dedicated Admin Connection (DAC).';
    RAISERROR(@ErrorMessage, 16, 1);
    RETURN;
END

/* ====================================================================================================================== */
/* ----------------------------------------- Check Input: --------------------------------------------------------------- */
/* ====================================================================================================================== */

SET @ObjectID = OBJECT_ID('[' + @EncryptedObjectOwnerOrSchema + '].[' + @EncryptedObjectName + ']');
IF  @ObjectID IS NULL
BEGIN
SET @ErrorMessage
    = N'Object [' + @EncryptedObjectOwnerOrSchema + N'].[' + @EncryptedObjectName
      + N'] does not exist in the database: [' + DB_NAME(DB_ID()) + N'].';
RAISERROR(@ErrorMessage, 16, 1);
RETURN;
END

IF NOT EXISTS
(
    SELECT      1
    FROM        sys.objects
    WHERE       [object_id] = @ObjectID
)
BEGIN
    SET @ErrorMessage
        = N'Object [' + @EncryptedObjectOwnerOrSchema + N'].[' + @EncryptedObjectName + N'] with ID: ['+CONVERT(VARCHAR(32), @ObjectID)+'] in database: ['
          + DB_NAME(DB_ID()) + N'] does not have an entry in sys.objects.';
    RAISERROR(@ErrorMessage, 16, 1);
    RETURN;
END;

IF OBJECTPROPERTY(@ObjectID, 'IsEncrypted') = 0
BEGIN
    SET @ErrorMessage
        = N'Object [' + @EncryptedObjectOwnerOrSchema + N'].[' + @EncryptedObjectName + N'] exists in the database: ['
          + DB_NAME(DB_ID()) + N'] but it is not encrypted.';
    RAISERROR(@ErrorMessage, 16, 1);
    RETURN;
END;

/* ====================================================================================================================== */
/* ----------------------------------------- Determine Object Type: ----------------------------------------------------- */
/* ====================================================================================================================== */

SELECT      @ObjectType =   so.[type]
FROM        sys.objects     so
WHERE       so.[object_id] = @ObjectID
AND         OBJECTPROPERTY(@ObjectID, 'IsEncrypted') = 1
IF  (@ObjectType IS NULL)
    BEGIN
            SET @ErrorMessage
                = N'Could not find Object Type in sys.objects for [' + @EncryptedObjectOwnerOrSchema + N'].[' + @EncryptedObjectName
                  + N'] in the database: [' + DB_NAME(DB_ID()) + N'].';
            RAISERROR(@ErrorMessage, 16, 1);
            RETURN;
    END

IF (@ObjectType NOT IN ('P', 'V', 'TR', 'FN', 'TF', 'IF'))
    BEGIN
        SET @ErrorMessage
            = N'Object [' + @EncryptedObjectOwnerOrSchema + N'].[' + @EncryptedObjectName + N'] exists in the database: ['
              + DB_NAME(DB_ID()) + N'] but the object type: ['+ @ObjectType +'] is not handled by this script. '
              +CHAR(10)+'Currently supported object-types are: '
              +CHAR(10)+'[P] - PROCEDURE,'
              +CHAR(10)+'[V] - VIEW,'
              +CHAR(10)+'[TR]- TRIGGER,'
              +CHAR(10)+'[FN]- FUNCTION,'
              +CHAR(10)+'[TF]- TABLE-VALUED FUNCTION,'
              +CHAR(10)+'[IF]- IN-LINED TABLE-VALUED FUNCTION';
        RAISERROR(@ErrorMessage, 16, 1);
        RETURN;
    END;

/* ====================================================================================================================== */
/* ----------------------------------------- If it's a trigger get its type: -------------------------------------------- */
/* ====================================================================================================================== */

IF (@ObjectType = 'TR')
	BEGIN
	     SELECT     @TriggerOnSchema = sch.[name],
	                @TriggerOnTable = OBJECT_NAME(tr.parent_id),
	                @TriggerForType = REPLACE(LTRIM(RTRIM(
	                                  CASE WHEN OBJECTPROPERTY(so.[object_id], 'ExecIsInsertTrigger') = 1 THEN 'INSERT ' ELSE '' END + 
	                                  CASE WHEN OBJECTPROPERTY(so.[object_id], 'ExecIsUpdateTrigger') = 1 THEN 'UPDATE ' ELSE '' END + 
	                                  CASE WHEN OBJECTPROPERTY(so.[object_id], 'ExecIsDeleteTrigger') = 1 THEN 'DELETE ' ELSE '' END)), ' ', ', ')
	     FROM       sys.objects  so
	     INNER JOIN sys.triggers tr  ON tr.object_id = so.object_id
	     INNER JOIN sys.tables   st  ON tr.parent_id = st.object_id
	     INNER JOIN sys.schemas  sch ON so.schema_id = sch.schema_id
	     WHERE      so.[type] = 'TR'
	     AND        so.[object_id] = @ObjectID;
	END

/* ====================================================================================================================== */
/* ----------------------------------------- Prepopulate @FakePlainTextObject header: ----------------------------------- */
/* ====================================================================================================================== */

SELECT  @RealEncryptedObject = imageval
FROM    sys.sysobjvalues
WHERE   [objid] = @ObjectID
AND     valclass = 1

SET     @ObjectDataLength = DATALENGTH(@RealEncryptedObject) / 2;

SELECT @FakePlainTextObject =
CASE   @ObjectType
       WHEN (N'P')  THEN N'ALTER PROCEDURE [' + @EncryptedObjectOwnerOrSchema + N'].[' + @EncryptedObjectName + N'] WITH ENCRYPTION AS'
       WHEN (N'V')  THEN N'ALTER VIEW ['      + @EncryptedObjectOwnerOrSchema + N'].[' + @EncryptedObjectName + N'] WITH ENCRYPTION AS SELECT 1 AS [1]'
       WHEN (N'TR') THEN N'ALTER TRIGGER ['   + @EncryptedObjectOwnerOrSchema + N'].[' + @EncryptedObjectName + N'] ON ['
                                              + @TriggerOnSchema + N'].['              + @TriggerOnTable + N'] WITH ENCRYPTION FOR ' + @TriggerForType + N' AS BEGIN SELECT 1 END'
       WHEN (N'FN') THEN N'ALTER FUNCTION ['  + @EncryptedObjectOwnerOrSchema + N'].[' + @EncryptedObjectName + N']() RETURNS INT WITH ENCRYPTION AS BEGIN RETURN 1 END'
       WHEN (N'TF') THEN N'ALTER FUNCTION ['  + @EncryptedObjectOwnerOrSchema + N'].[' + @EncryptedObjectName + N']() RETURNS @t TABLE (p1 INT) WITH ENCRYPTION AS BEGIN INSERT @t SELECT 1 RETURN END'
       WHEN (N'IF') THEN N'ALTER FUNCTION ['  + @EncryptedObjectOwnerOrSchema + N'].[' + @EncryptedObjectName + N']() RETURNS TABLE WITH ENCRYPTION AS RETURN (SELECT 1 AS [1])'
END

/* ====================================================================================================================== */
/* ----------------------------------------- Pad the rest of @FakePlainTextObject with dashes: -------------------------- */
/* ====================================================================================================================== */

WHILE DATALENGTH(@FakePlainTextObject) / 2 < @ObjectDataLength
	  BEGIN
	      IF DATALENGTH(@FakePlainTextObject) / 2 + 4000 < @ObjectDataLength
	          SET @FakePlainTextObject = @FakePlainTextObject + REPLICATE(N'-', 4000);
	      ELSE
	          SET @FakePlainTextObject
	              = @FakePlainTextObject + REPLICATE(N'-', @ObjectDataLength - (DATALENGTH(@FakePlainTextObject) / 2));
	  END;

/* ====================================================================================================================== */
/* ----------------------------------------- Create @FakePlainTextObject to store  -------------------------------------- */
/* ----------------------------------------- its encrypted version in @FakeEncryptedObject: ----------------------------- */
/* ====================================================================================================================== */

/* SET XACT_ABORT OFF; */
BEGIN TRAN;
    EXEC(@FakePlainTextObject);
    
    SELECT  @FakeEncryptedObject = imageval
    FROM    sys.sysobjvalues
    WHERE   [objid] = @ObjectID
    AND     valclass = 1

IF @@TRANCOUNT > 0
BEGIN
    /* Now that the FakePlainTextObject is created we can rollback its creation to keep the real object as it was */
    ROLLBACK TRAN;
END

SET @FakePlainTextObject = REPLACE(@FakePlainTextObject, 'ALTER PROCEDURE', 'CREATE PROCEDURE');
SET @FakePlainTextObject = REPLACE(@FakePlainTextObject, 'ALTER VIEW', 'CREATE VIEW');
SET @FakePlainTextObject = REPLACE(@FakePlainTextObject, 'ALTER FUNCTION', 'CREATE FUNCTION');
SET @FakePlainTextObject = REPLACE(@FakePlainTextObject, 'ALTER TRIGGER', 'CREATE TRIGGER');

/* ====================================================================================================================== */
/* ----------------------------------------- Pad @RealDecryptedObject with placeholder characters:  --------------------- */
/* ====================================================================================================================== */

SET @RealDecryptedObject = N'';
WHILE DATALENGTH(@RealDecryptedObject) / 2 < @ObjectDataLength
BEGIN
    IF DATALENGTH(@RealDecryptedObject) / 2 + 4000 < @ObjectDataLength
        SET @RealDecryptedObject = @RealDecryptedObject + REPLICATE(N'*', 4000);
    ELSE
        SET @RealDecryptedObject
            = @RealDecryptedObject
              + REPLICATE(N'*', @ObjectDataLength - (DATALENGTH(@RealDecryptedObject) / 2));
END;

/* ====================================================================================================================== */
/* ----------------------------------------- Do the actual decryption into @RealDecryptedObject:  ----------------------- */
/* ====================================================================================================================== */

SET @PointerDecryptedString = 1;
WHILE (@PointerDecryptedString <= @ObjectDataLength)
BEGIN
    /*  
        Replace 1 character at a time in the @RealDecryptedObject at the @PointerDecryptedString position
        with the result of XOR operation (^) between @RealEncryptedObject and the Encryption Key for each character;
		Encryption Key is obtained by applying XOR operation (^) between @FakePlainTextObject and @FakeEncryptedObject
    */
    SET @RealDecryptedObject
        = STUFF(
                   @RealDecryptedObject,
                   @PointerDecryptedString,
                   1,
                   NCHAR(UNICODE(SUBSTRING(@RealEncryptedObject, @PointerDecryptedString, 1))
                         ^ (UNICODE(SUBSTRING(@FakePlainTextObject, @PointerDecryptedString, 1))
                            ^ UNICODE(SUBSTRING(@FakeEncryptedObject, @PointerDecryptedString, 1))
                           )
                        )
               );
    SET @PointerDecryptedString = @PointerDecryptedString + 1;
END;

/* ====================================================================================================================== */
/* ----------------------------------------- Comment out the 'WITH ENCRYPTION' clause:  --------------------------------- */
/* ====================================================================================================================== */

IF (CHARINDEX('WITH ENCRYPTION', @RealDecryptedObject COLLATE Latin1_General_CI_AI)) > 0
BEGIN
    /* COLLATE Latin1_General_CI_AI makes below Case-Insensitive (valid for both: 'WITH ENCRYPTION' and 'with encryption'): */
    SET @RealDecryptedObject = REPLACE(@RealDecryptedObject COLLATE Latin1_General_CI_AI, 'WITH ENCRYPTION', '/* WITH ENCRYPTION */')
END

IF (@CreateDecryptedVersion = 1)
BEGIN
    DECLARE @EncryptedObjectNewName SYSNAME = @EncryptedObjectName + '_ENCRYPTED';
    DECLARE @RenameResult INT
    EXEC @RenameResult = sp_rename @objname = @EncryptedObjectName, @newname = @EncryptedObjectNewName;
    IF @RenameResult <> 0
    BEGIN
        SET @ErrorMessage = CONCAT(N'sp_rename returned: ', ERROR_MESSAGE()) 
        RAISERROR(@ErrorMessage, 16, 1);
    END
    ELSE
    BEGIN
        PRINT(CONCAT('Successfully renamed: ', QUOTENAME(@EncryptedObjectName), ' to: ', QUOTENAME(@EncryptedObjectNewName)));
    BEGIN TRY
        BEGIN TRY
            EXECUTE sp_executesql @stmt = @RealDecryptedObject;
            PRINT(CONCAT('Successfully created decrypted version of: ', QUOTENAME(@EncryptedObjectName)));
        END TRY
        BEGIN CATCH   
            SELECT
                 @ErrorNumber = ERROR_NUMBER()
                ,@ErrorMessage = ERROR_MESSAGE()
                ,@ErrorSeverity = ERROR_SEVERITY()
                ,@ErrorState = ERROR_STATE()
                ,@ErrorLine = ERROR_LINE();
    
            RAISERROR('Error %d caught in @RealDecryptedObject at line %d: %s'
                ,@ErrorSeverity
                ,@ErrorState
                ,@ErrorNumber
                ,@ErrorLine
                ,@ErrorMessage);
    
        END CATCH; 
    END TRY
    BEGIN CATCH  
        THROW;
    END CATCH; 
    END
END

/* ====================================================================================================================== */
/* ----------------------------------------- Print out (and output) results: -------------------------------------------- */
/* ====================================================================================================================== */

IF (@PrintOutObjectDefinition = 1)
BEGIN
    SET @PointerDecryptedString = 0;
    SET @PointerBeginOfNewLine = -2; /* (-2) because at first iteration we want to catch the first 2 characters of the first line */
    
    WHILE @PointerDecryptedString <= LEN(@RealDecryptedObject)
    BEGIN
        IF ((SUBSTRING(@RealDecryptedObject, @PointerDecryptedString + 1, 2) = @CrLf) OR (@PointerDecryptedString = LEN(@RealDecryptedObject)))
        BEGIN
            SELECT @DecryptedLineOfCode

                = REPLACE(REPLACE(
                  SUBSTRING(@RealDecryptedObject, @PointerBeginOfNewLine + LEN(@CrLf), (@PointerDecryptedString - @PointerBeginOfNewLine))
                  , CHAR(13), ''), CHAR(10), '')
            
            PRINT (@DecryptedLineOfCode);
            INSERT INTO [#ObjectDefinition]
            (
                [DecryptedLineOfCode]
            )
            VALUES (@DecryptedLineOfCode);
            SET @PointerBeginOfNewLine = @PointerDecryptedString;
        END
        SET @PointerDecryptedString = @PointerDecryptedString + 1;
    END;
    
    SELECT 
             [LineId],
             [DecryptedLineOfCode]
    FROM     [#ObjectDefinition] 
    ORDER BY [LineId]
END

/*
--Check length of each object:
SELECT LEN(@RealEncryptedObject) AS [Length_Real_Object],
       LEN(@FakePlainTextObject) AS [Length_Fake_Object],
       LEN(@FakeEncryptedObject) AS [Length_Temp_Fake_Object],
       LEN(@RealDecryptedObject) AS [Length_Decrypted_Object]
*/
