﻿using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;

namespace iCOR3.iSqlDatabase
{
	/// <summary>
	/// Basic MS SQL methods class.
	/// Supports asynchronous database data retrieval and synchronous data updates. 
	/// </summary>
	public class Sql : IDisposable
	{
		#region Constants
		int CMD_TIMEOUT = 300;
		#endregion

		#region Variables
		private bool bDisposed;
		private int _commandTimeout;
		private string _connectionString;
		private System.Data.SqlClient.SqlConnection _sqlConnection;
		#endregion

		#region Properties
		public int CommandTimeout
		{
			get
			{
				return this._commandTimeout;
			}
			set
			{
				this._commandTimeout = value;
			}
		}

		public string ConnectionString
		{
			get
			{
				return this._connectionString;
			}
			set
			{
				this._connectionString = value;
			}
		}

		public System.Data.SqlClient.SqlConnection SqlConnection
		{
			get
			{
				return this._sqlConnection;
			}
			set
			{
				this._sqlConnection = value;
			}
		}
		#endregion

		#region Constructors
		public Sql(string SqlConnectionString)
		{
			this.bDisposed = false;

			this.CommandTimeout = CMD_TIMEOUT;
			this.ConnectionString = SqlConnectionString;
		}
		public Sql(string SqlConnectionString, int CommandTimeout)
		{
			this.bDisposed = false;
			this.CommandTimeout = CommandTimeout;
			this.ConnectionString = SqlConnectionString;
		}
		public Sql(System.Data.SqlClient.SqlConnection sqlConnection)
		{
			this.bDisposed = false;

			this.CommandTimeout = CMD_TIMEOUT;
			this.SqlConnection = sqlConnection;
			if (this.SqlConnection.State != ConnectionState.Open) this.SqlConnection.Open();
		}
		public Sql(System.Data.SqlClient.SqlConnection sqlConnection, int CommandTimeout)
		{
			this.bDisposed = false;

			this.CommandTimeout = CommandTimeout;
			this.SqlConnection = sqlConnection;
			if (this.SqlConnection.State != ConnectionState.Open) this.SqlConnection.Open();
		}
		#endregion

		#region Public Methods
		public IEnumerable<SortedList<string, object>> RetrieveData(string SqlQuery)
		{
			using (System.Data.SqlClient.SqlConnection sqlConnection = new System.Data.SqlClient.SqlConnection(this.ConnectionString))
			{
				try
				{
					sqlConnection.Open();
				}
				catch (Exception eX)
				{
					throw new Exception(string.Format("{0}::{1}", new StackFrame(0, true).GetMethod().Name, eX.Message));
				}

				using (System.Data.SqlClient.SqlCommand sqlCommand = new System.Data.SqlClient.SqlCommand(SqlQuery, sqlConnection))
				{
					sqlCommand.CommandTimeout = this.CommandTimeout;
					using (System.Data.SqlClient.SqlDataReader sqlReader = sqlCommand.ExecuteReader())
					{
						while (sqlReader.Read())
						{
							SortedList<string, object> dicRecord = new SortedList<string, object>(StringComparer.OrdinalIgnoreCase);
							for (int i = 0; i < sqlReader.FieldCount; i++)
							{
								string sKey = sqlReader.GetName(i);

								if (!dicRecord.ContainsKey(sKey))
								{
									dicRecord.Add(sKey, sqlReader.GetValue(i));
								}
							}
							yield return dicRecord;
						}
					}
				}
			}
		}
		public void ExecuteNonSqlQuery(string SqlQuery)
		{
			try
			{
				if (this.SqlConnection != null)
				{
					using (System.Data.SqlClient.SqlCommand sqlCommand = new System.Data.SqlClient.SqlCommand(SqlQuery, this.SqlConnection))
					{
						sqlCommand.CommandTimeout = this.CommandTimeout;
						sqlCommand.ExecuteNonQuery();
					}
				}
				else
				{
					using (System.Data.SqlClient.SqlConnection sqlConnection = new System.Data.SqlClient.SqlConnection(this.ConnectionString))
					{
						try
						{
							sqlConnection.Open();
						}
						catch (Exception eX)
						{
							throw new Exception(string.Format("{0}::{1}", new StackFrame(0, true).GetMethod().Name, eX.Message));
						}
						using (System.Data.SqlClient.SqlCommand sqlCommand = new System.Data.SqlClient.SqlCommand(SqlQuery, sqlConnection))
						{
							sqlCommand.CommandTimeout = this.CommandTimeout;
							sqlCommand.ExecuteNonQuery();
						}
					}
				}
			}
			catch (Exception eX)
			{
				throw new Exception(string.Format("{0}::{1}", new StackFrame(0, true).GetMethod().Name, eX.Message));
			}
		}
		#endregion

		#region IDisposable Members
		public void Dispose()
		{
			Dispose(true);
			GC.SuppressFinalize(this);
		}

		protected virtual void Dispose(bool bDisposing)
		{
			if (!this.bDisposed)
			{
				if (bDisposing)
				{
					if (this.SqlConnection != null)
					{
						this.SqlConnection.Dispose();
					}
				}

				this.bDisposed = true;
			}
		}
		#endregion
	}
}
